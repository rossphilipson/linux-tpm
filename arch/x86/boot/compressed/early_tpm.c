// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Apertus Solutions, LLC
 *
 * Author(s):
 *      Daniel P. Smith <dpsmith@apertussolutions.com>
 *
 * The code in this file is based on the article "Writing a TPM Device Driver"
 * published on http://ptgmedia.pearsoncmg.com.
 *
 */

#include <linux/types.h>
#include <linux/bits.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <asm/byteorder.h>
#include <asm/io.h>

#define COMPRESSED_KERNEL
#include <crypto/sha.h>
#include <linux/tpm_buffer.h>
#include <linux/tpm_command.h>
#include <linux/tpm_core.h>
#include "../../../../drivers/char/tpm/tpm_tis_defs.h"
#include "early_tpm.h"

#define tpm_read8(f) readb((void *)(u64)(TPM_MMIO_BASE | f))
#define tpm_write8(v, f) writeb(v, (void *)(u64)(TPM_MMIO_BASE | f))
#define tpm_read32(f) readl((void *)(u64)(TPM_MMIO_BASE | f));

static struct tpm tpm;
static u8 locality = TPM_NO_LOCALITY;

static void tpm_io_delay(void)
{
	/* This is the default delay type in native_io_delay */
	asm volatile ("outb %al, $0x80");
}

static void tpm_udelay(int loops)
{
	while (loops--)
		tpm_io_delay();	/* Approximately 1 us */
}

static void tpm_mdelay(int ms)
{
	int i;

	for (i = 0; i < ms; i++)
		tpm_udelay(1000);
}

static u32 burst_wait(void)
{
	u32 count = 0;

	while (count == 0) {
		count = tpm_read8(TPM_STS(locality) + 1);
		count += tpm_read8(TPM_STS(locality) + 2) << 8;

		/* Wait for FIFO to drain */
		if (count == 0)
			tpm_udelay(TPM_BURST_MIN_DELAY);
	}

	return count;
}

static void tis_relinquish_locality(void)
{
	if (locality < TPM_MAX_LOCALITY)
		tpm_write8(TPM_ACCESS_ACTIVE_LOCALITY, TPM_ACCESS(locality));

	locality = TPM_NO_LOCALITY;
}

static u8 tis_request_locality(u8 l)
{
	if (l > TPM_MAX_LOCALITY)
		return TPM_NO_LOCALITY;

	if (l == locality)
		return locality;

	tis_relinquish_locality();

	tpm_write8(TPM_ACCESS_REQUEST_USE, TPM_ACCESS(l));

	/* wait for locality to be granted */
	if (tpm_read8(TPM_ACCESS(l)) & TPM_ACCESS_ACTIVE_LOCALITY)
		locality = l;

	return locality;
}

static size_t tis_send(struct tpm_buf *buf)
{
	u8 status, *buf_ptr;
	u32 length, count = 0, burstcnt = 0;

	if (locality > TPM_MAX_LOCALITY)
		return 0;

	for (status = 0; (status & TPM_STS_COMMAND_READY) == 0; ) {
		tpm_write8(TPM_STS_COMMAND_READY, TPM_STS(locality));
		status = tpm_read8(TPM_STS(locality));
	}

	buf_ptr = buf->data;
	length = tpm_buf_length(buf);

	/* send all but the last byte */
	while (count < (length - 1)) {
		burstcnt = burst_wait();
		for (; burstcnt > 0 && count < (length - 1); burstcnt--) {
			tpm_write8(buf_ptr[count], TPM_DATA_FIFO(locality));
			count++;
		}

		/* check for overflow */
		for (status = 0; (status & TPM_STS_VALID) == 0; )
			status = tpm_read8(TPM_STS(locality));

		if ((status & TPM_STS_DATA_EXPECT) == 0)
			return 0;
	}

	/* write last byte */
	tpm_write8(buf_ptr[length - 1], TPM_DATA_FIFO(locality));
	count++;

	/* make sure it stuck */
	for (status = 0; (status & TPM_STS_VALID) == 0; )
		status = tpm_read8(TPM_STS(locality));

	if ((status & TPM_STS_DATA_EXPECT) != 0)
		return 0;

	/* go and do it */
	tpm_write8(TPM_STS_GO, TPM_STS(locality));

	return (size_t)count;
}

static u8 tis_init(struct tpm *t)
{
	locality = TPM_NO_LOCALITY;

	if (tis_request_locality(0) != 0)
		return 0;

	t->vendor = tpm_read32(TPM_DID_VID(0));
	if ((t->vendor & 0xFFFF) == 0xFFFF)
		return 0;

	return 1;
}

static u16 tpm_alg_size(u16 alg_id)
{
	switch (alg_id) {
	case TPM_ALG_SHA1:
		return SHA1_DIGEST_SIZE;
	case TPM_ALG_SHA256:
	case TPM_ALG_SM3_256:
		return SHA256_DIGEST_SIZE;
	case TPM_ALG_SHA384:
		return SHA384_DIGEST_SIZE;
	case TPM_ALG_SHA512:
		return SHA512_DIGEST_SIZE;
	default:
		;
	}

	return 0;
}

static int tpm1_pcr_extend(struct tpm *t, u32 pcr, struct tpm_digest *d)
{
	struct tpm_buf buf;
	int ret;

	ret = tpm_buf_init(&buf, TPM_TAG_RQU_COMMAND, TPM_ORD_PCR_EXTEND);
	if (ret)
		return ret;

	tpm_buf_append_u32(&buf, pcr);
	tpm_buf_append(&buf, d->digest, tpm_alg_size(TPM_ALG_SHA1));

	if (tpm_buf_length(&buf) != tis_send(&buf))
		ret = -EAGAIN;

	return ret;
}

static int tpm2_extend_pcr(struct tpm *t, u32 pcr, u32 count,
			   struct tpm_digest *digests)
{
	struct tpm_buf buf;
	u8 auth_area[NULL_AUTH_SIZE] = {0};
	u32 *handle;
	int ret, i;

	ret = tpm_buf_init(&buf, TPM2_ST_SESSIONS, TPM2_CC_PCR_EXTEND);
	if (ret)
		return ret;

	tpm_buf_append_u32(&buf, pcr);

	/*
	 * The handle, the first element, is the
	 * only non-zero value in a NULL auth
	 */
	handle = (u32 *)&auth_area;
	*handle = cpu_to_be32(TPM2_RS_PW);

	tpm_buf_append_u32(&buf, NULL_AUTH_SIZE);
	tpm_buf_append(&buf, (const unsigned char *)&auth_area,
                       NULL_AUTH_SIZE);

        tpm_buf_append_u32(&buf, count);

	for (i = 0; i < count; i++) {
		tpm_buf_append_u16(&buf, digests[i].alg_id);
		tpm_buf_append(&buf, (const unsigned char *)&digests[i].digest,
			       tpm_alg_size(digests[i].alg_id));
	}

	if (tpm_buf_length(&buf) != tis_send(&buf))
		ret = -EAGAIN;

	return ret;
}

static void find_interface_and_family(struct tpm *t)
{
	struct tpm_interface_id intf_id;
	struct tpm_intf_capability intf_cap;

	/* Sort out whether if it is 1.2 */
	intf_cap.val = tpm_read32(TPM_INTF_CAPABILITY_0);
	if ((intf_cap.interface_version == TPM12_TIS_INTF_12) ||
	    (intf_cap.interface_version == TPM12_TIS_INTF_13)) {
		t->family = TPM12;
		t->intf = TPM_TIS;
		return;
	}

	/* Assume that it is 2.0 and TIS */
	t->family = TPM20;
	t->intf = TPM_TIS;

	/* Check if the interface is CRB */
	intf_id.val = tpm_read32(TPM_INTERFACE_ID_0);
	if (intf_id.interface_type == TPM_CRB_INTF_ACTIVE)
		t->intf = TPM_CRB;
}

struct tpm *enable_tpm(void)
{
	struct tpm *t = &tpm;

	find_interface_and_family(t);

	switch (t->intf) {
	case TPM_TIS:
		if (!tis_init(t))
			return NULL;
		break;
	case TPM_CRB:
		return NULL;
	}

	return t;
}

u8 tpm_request_locality(u8 l)
{
	return tis_request_locality(l);
}

int tpm_extend_pcr(struct tpm *t, u32 pcr, u16 algo,
		u8 *digest)
{
	int ret = 0;

	if (t->family == TPM12) {
		struct tpm_digest d;

		if (algo != TPM_ALG_SHA1)
			return -EINVAL;

		memcpy((void *)d.digest, digest, SHA1_DIGEST_SIZE);

		ret = tpm1_pcr_extend(t, pcr, &d);
	} else if (t->family == TPM20) {
		struct tpm_digest *d;
		u8 buf[MAX_TPM_EXTEND_SIZE];

		d = (struct tpm_digest *) buf;
		d->alg_id = algo;
		switch (algo) {
		case TPM_ALG_SHA1:
			memcpy(d->digest, digest, SHA1_DIGEST_SIZE);
			break;
		case TPM_ALG_SHA256:
		case TPM_ALG_SM3_256:
			memcpy(d->digest, digest, SHA256_DIGEST_SIZE);
			break;
		case TPM_ALG_SHA384:
			memcpy(d->digest, digest, SHA384_DIGEST_SIZE);
			break;
		case TPM_ALG_SHA512:
			memcpy(d->digest, digest, SHA512_DIGEST_SIZE);
			break;
		default:
			return -EINVAL;
		}

		ret = tpm2_extend_pcr(t, pcr, 1, d);
	} else
		ret = -EINVAL;

	return ret;
}

void free_tpm(void)
{
	tis_relinquish_locality();
}
