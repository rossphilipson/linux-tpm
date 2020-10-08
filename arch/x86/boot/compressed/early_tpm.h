/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2020 Apertus Solutions, LLC
 *
 * Author(s):
 *      Daniel P. Smith <dpsmith@apertussolutions.com>
 *
 */

#ifndef BOOT_COMPRESSED_EARLY_TPM_H
#define BOOT_COMPRESSED_EARLY_TPM_H

#define TPM_MMIO_BASE		0xFED40000
#define TPM_MAX_LOCALITY	4
#define TPM_NO_LOCALITY		0xFF
#define TPM_BURST_MIN_DELAY	100 /* 100us */
#define TPM_ORD_PCR_EXTEND	20
#define NULL_AUTH_SIZE		9
#define MAX_TPM_EXTEND_SIZE	68 /* TPM2 SHA512 is the largest */

#define TPM_INTERFACE_ID_0	0x30
#define TPM_TIS_INTF_ACTIVE	0x00
#define TPM_CRB_INTF_ACTIVE	0x01

struct tpm_interface_id {
	union {
		u32 val;
		struct {
			u32 interface_type:4;
			u32 interface_version:4;
			u32 cap_locality:1;
			u32 reserved1:4;
			u32 cap_tis:1;
			u32 cap_crb:1;
			u32 cap_if_res:2;
			u32 interface_selector:2;
			u32 intf_sel_lock:1;
			u32 reserved2:4;
			u32 reserved3:8;
		};
	};
} __packed;

#define TPM_INTF_CAPABILITY_0	0x14
#define TPM12_TIS_INTF_12	0x00
#define TPM12_TIS_INTF_13	0x02
#define TPM20_TIS_INTF_13	0x03

struct tpm_intf_capability {
	union {
		u32 val;
		struct {
			u32 data_avail_int_support:1;
			u32 sts_valid_int_support:1;
			u32 locality_change_int_support:1;
			u32 interrupt_level_high:1;
			u32 interrupt_level_low:1;
			u32 interrupt_edge_rising:1;
			u32 interrupt_edge_falling:1;
			u32 command_ready_int_support:1;
			u32 burst_count_static:1;
			u32 data_transfer_size_support:2;
			u32 reserved1:17;
			u32 interface_version:3;
			u32 reserved2:1;
		};
	};
} __packed;

enum tpm_hw_intf {
	TPM_TIS,
	TPM_CRB
};

enum tpm_family {
	TPM12,
	TPM20
};

struct tpm {
	u32 vendor;
	enum tpm_family family;
	enum tpm_hw_intf intf;
};

extern struct tpm *enable_tpm(void);
extern u8 tpm_request_locality(u8 l);
extern int tpm_extend_pcr(struct tpm *t, u32 pcr, u16 algo,
			  u8 *digest);
extern void free_tpm(void);

#endif
