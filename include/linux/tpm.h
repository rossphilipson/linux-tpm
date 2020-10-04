/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2004,2007,2008 IBM Corporation
 *
 * Authors:
 * Leendert van Doorn <leendert@watson.ibm.com>
 * Dave Safford <safford@watson.ibm.com>
 * Reiner Sailer <sailer@watson.ibm.com>
 * Kylene Hall <kjhall@us.ibm.com>
 * Debora Velarde <dvelarde@us.ibm.com>
 *
 * Maintained by: <tpmdd_devel@lists.sourceforge.net>
 *
 * Device driver for TCG/TCPA TPM (trusted platform module).
 * Specifications at www.trustedcomputinggroup.org
 */
#ifndef __LINUX_TPM_H__
#define __LINUX_TPM_H__

#include <linux/hw_random.h>
#include <linux/acpi.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <crypto/hash_info.h>
#include <linux/tpm_buffer.h>
#include <linux/tpm_core.h>

struct tpm_chip;
struct trusted_key_payload;
struct trusted_key_options;

struct tpm_class_ops {
	unsigned int flags;
	const u8 req_complete_mask;
	const u8 req_complete_val;
	bool (*req_canceled)(struct tpm_chip *chip, u8 status);
	int (*recv) (struct tpm_chip *chip, u8 *buf, size_t len);
	int (*send) (struct tpm_chip *chip, u8 *buf, size_t len);
	void (*cancel) (struct tpm_chip *chip);
	u8 (*status) (struct tpm_chip *chip);
	void (*update_timeouts)(struct tpm_chip *chip,
				unsigned long *timeout_cap);
	void (*update_durations)(struct tpm_chip *chip,
				 unsigned long *duration_cap);
	int (*go_idle)(struct tpm_chip *chip);
	int (*cmd_ready)(struct tpm_chip *chip);
	int (*request_locality)(struct tpm_chip *chip, int loc);
	int (*relinquish_locality)(struct tpm_chip *chip, int loc);
	void (*clk_enable)(struct tpm_chip *chip, bool value);
};

#define TPM_NUM_EVENT_LOG_FILES		3

struct tpm_bios_log {
	void *bios_event_log;
	void *bios_event_log_end;
};

struct tpm_chip_seqops {
	struct tpm_chip *chip;
	const struct seq_operations *seqops;
};

struct tpm_chip {
	struct device dev;
	struct device devs;
	struct cdev cdev;
	struct cdev cdevs;

	/* A driver callback under ops cannot be run unless ops_sem is held
	 * (sometimes implicitly, eg for the sysfs code). ops becomes null
	 * when the driver is unregistered, see tpm_try_get_ops.
	 */
	struct rw_semaphore ops_sem;
	const struct tpm_class_ops *ops;

	struct tpm_bios_log log;
	struct tpm_chip_seqops bin_log_seqops;
	struct tpm_chip_seqops ascii_log_seqops;

	unsigned int flags;

	int dev_num;		/* /dev/tpm# */
	unsigned long is_open;	/* only one allowed */

	char hwrng_name[64];
	struct hwrng hwrng;

	struct mutex tpm_mutex;	/* tpm is processing */

	unsigned long timeout_a; /* jiffies */
	unsigned long timeout_b; /* jiffies */
	unsigned long timeout_c; /* jiffies */
	unsigned long timeout_d; /* jiffies */
	bool timeout_adjusted;
	unsigned long duration[TPM_NUM_DURATIONS]; /* jiffies */
	bool duration_adjusted;

	struct dentry *bios_dir[TPM_NUM_EVENT_LOG_FILES];

	const struct attribute_group *groups[3];
	unsigned int groups_cnt;

	u32 nr_allocated_banks;
	struct tpm_bank_info *allocated_banks;
#ifdef CONFIG_ACPI
	acpi_handle acpi_dev_handle;
	char ppi_version[TPM_PPI_VERSION_LEN + 1];
#endif /* CONFIG_ACPI */

	struct tpm_space work_space;
	u32 last_cc;
	u32 nr_commands;
	u32 *cc_attrs_tbl;

	/* active locality */
	int locality;
};

enum tpm_chip_flags {
	TPM_CHIP_FLAG_TPM2		= BIT(1),
	TPM_CHIP_FLAG_IRQ		= BIT(2),
	TPM_CHIP_FLAG_VIRTUAL		= BIT(3),
	TPM_CHIP_FLAG_HAVE_TIMEOUTS	= BIT(4),
	TPM_CHIP_FLAG_ALWAYS_POWERED	= BIT(5),
	TPM_CHIP_FLAG_FIRMWARE_POWER_MANAGED	= BIT(6),
};

#define to_tpm_chip(d) container_of(d, struct tpm_chip, dev)

#if defined(CONFIG_TCG_TPM) || defined(CONFIG_TCG_TPM_MODULE)

extern int tpm_is_tpm2(struct tpm_chip *chip);
extern int tpm_pcr_read(struct tpm_chip *chip, u32 pcr_idx,
			struct tpm_digest *digest);
extern int tpm_pcr_extend(struct tpm_chip *chip, u32 pcr_idx,
			  struct tpm_digest *digests);
extern int tpm_send(struct tpm_chip *chip, void *cmd, size_t buflen);
extern int tpm_get_random(struct tpm_chip *chip, u8 *data, size_t max);
extern struct tpm_chip *tpm_default_chip(void);
void tpm2_flush_context(struct tpm_chip *chip, u32 handle);
#else
static inline int tpm_is_tpm2(struct tpm_chip *chip)
{
	return -ENODEV;
}

static inline int tpm_pcr_read(struct tpm_chip *chip, int pcr_idx,
			       struct tpm_digest *digest)
{
	return -ENODEV;
}

static inline int tpm_pcr_extend(struct tpm_chip *chip, u32 pcr_idx,
				 struct tpm_digest *digests)
{
	return -ENODEV;
}

static inline int tpm_send(struct tpm_chip *chip, void *cmd, size_t buflen)
{
	return -ENODEV;
}
static inline int tpm_get_random(struct tpm_chip *chip, u8 *data, size_t max)
{
	return -ENODEV;
}

static inline struct tpm_chip *tpm_default_chip(void)
{
	return NULL;
}
#endif
#endif
