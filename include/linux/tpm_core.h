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
#ifndef __LINUX_TPM_CORE_H__
#define __LINUX_TPM_CORE_H__

#define TPM_DIGEST_SIZE 20	/* Max TPM v1.2 PCR size */
#define TPM_MAX_DIGEST_SIZE SHA512_DIGEST_SIZE

enum tpm_algorithms {
	TPM_ALG_ERROR		= 0x0000,
	TPM_ALG_SHA1		= 0x0004,
	TPM_ALG_KEYEDHASH	= 0x0008,
	TPM_ALG_SHA256		= 0x000B,
	TPM_ALG_SHA384		= 0x000C,
	TPM_ALG_SHA512		= 0x000D,
	TPM_ALG_NULL		= 0x0010,
	TPM_ALG_SM3_256		= 0x0012,
};

struct tpm_digest {
	u16 alg_id;
	u8 digest[TPM_MAX_DIGEST_SIZE];
} __packed;

struct tpm_bank_info {
	u16 alg_id;
	u16 digest_size;
	u16 crypto_id;
};

enum TPM_OPS_FLAGS {
	TPM_OPS_AUTO_STARTUP = BIT(0),
};

/* Indexes the duration array */
enum tpm_duration {
	TPM_SHORT = 0,
	TPM_MEDIUM = 1,
	TPM_LONG = 2,
	TPM_LONG_LONG = 3,
	TPM_UNDEFINED,
	TPM_NUM_DURATIONS = TPM_UNDEFINED,
};

#define TPM_PPI_VERSION_LEN		3

struct tpm_space {
	u32 context_tbl[3];
	u8 *context_buf;
	u32 session_tbl[3];
	u8 *session_buf;
	u32 buf_size;
};

#define TPM_HEADER_SIZE		10

enum tpm2_const {
	TPM2_PLATFORM_PCR       =     24,
	TPM2_PCR_SELECT_MIN     = ((TPM2_PLATFORM_PCR + 7) / 8),
};

enum tpm2_timeouts {
	TPM2_TIMEOUT_A          =    750,
	TPM2_TIMEOUT_B          =   2000,
	TPM2_TIMEOUT_C          =    200,
	TPM2_TIMEOUT_D          =     30,
	TPM2_DURATION_SHORT     =     20,
	TPM2_DURATION_MEDIUM    =    750,
	TPM2_DURATION_LONG      =   2000,
	TPM2_DURATION_LONG_LONG = 300000,
	TPM2_DURATION_DEFAULT   = 120000,
};

enum tpm2_structures {
	TPM2_ST_NO_SESSIONS	= 0x8001,
	TPM2_ST_SESSIONS	= 0x8002,
};

/* Indicates from what layer of the software stack the error comes from */
#define TSS2_RC_LAYER_SHIFT	 16
#define TSS2_RESMGR_TPM_RC_LAYER (11 << TSS2_RC_LAYER_SHIFT)

enum tpm2_return_codes {
	TPM2_RC_SUCCESS		= 0x0000,
	TPM2_RC_HASH		= 0x0083, /* RC_FMT1 */
	TPM2_RC_HANDLE		= 0x008B,
	TPM2_RC_INITIALIZE	= 0x0100, /* RC_VER1 */
	TPM2_RC_FAILURE		= 0x0101,
	TPM2_RC_DISABLED	= 0x0120,
	TPM2_RC_COMMAND_CODE    = 0x0143,
	TPM2_RC_TESTING		= 0x090A, /* RC_WARN */
	TPM2_RC_REFERENCE_H0	= 0x0910,
	TPM2_RC_RETRY		= 0x0922,
};

enum tpm2_command_codes {
	TPM2_CC_FIRST		        = 0x011F,
	TPM2_CC_HIERARCHY_CONTROL       = 0x0121,
	TPM2_CC_HIERARCHY_CHANGE_AUTH   = 0x0129,
	TPM2_CC_CREATE_PRIMARY          = 0x0131,
	TPM2_CC_SEQUENCE_COMPLETE       = 0x013E,
	TPM2_CC_SELF_TEST	        = 0x0143,
	TPM2_CC_STARTUP		        = 0x0144,
	TPM2_CC_SHUTDOWN	        = 0x0145,
	TPM2_CC_NV_READ                 = 0x014E,
	TPM2_CC_CREATE		        = 0x0153,
	TPM2_CC_LOAD		        = 0x0157,
	TPM2_CC_SEQUENCE_UPDATE         = 0x015C,
	TPM2_CC_UNSEAL		        = 0x015E,
	TPM2_CC_CONTEXT_LOAD	        = 0x0161,
	TPM2_CC_CONTEXT_SAVE	        = 0x0162,
	TPM2_CC_FLUSH_CONTEXT	        = 0x0165,
	TPM2_CC_VERIFY_SIGNATURE        = 0x0177,
	TPM2_CC_GET_CAPABILITY	        = 0x017A,
	TPM2_CC_GET_RANDOM	        = 0x017B,
	TPM2_CC_PCR_READ	        = 0x017E,
	TPM2_CC_PCR_EXTEND	        = 0x0182,
	TPM2_CC_EVENT_SEQUENCE_COMPLETE = 0x0185,
	TPM2_CC_HASH_SEQUENCE_START     = 0x0186,
	TPM2_CC_CREATE_LOADED           = 0x0191,
	TPM2_CC_LAST		        = 0x0193, /* Spec 1.36 */
};

enum tpm2_permanent_handles {
	TPM2_RS_PW		= 0x40000009,
};

enum tpm2_capabilities {
	TPM2_CAP_HANDLES	= 1,
	TPM2_CAP_COMMANDS	= 2,
	TPM2_CAP_PCRS		= 5,
	TPM2_CAP_TPM_PROPERTIES = 6,
};

enum tpm2_properties {
	TPM_PT_TOTAL_COMMANDS	= 0x0129,
};

enum tpm2_startup_types {
	TPM2_SU_CLEAR	= 0x0000,
	TPM2_SU_STATE	= 0x0001,
};

enum tpm2_cc_attrs {
	TPM2_CC_ATTR_CHANDLES	= 25,
	TPM2_CC_ATTR_RHANDLE	= 28,
};

#define TPM_VID_INTEL    0x8086
#define TPM_VID_WINBOND  0x1050
#define TPM_VID_STM      0x104A

enum tpm2_object_attributes {
	TPM2_OA_USER_WITH_AUTH		= BIT(6),
};

enum tpm2_session_attributes {
	TPM2_SA_CONTINUE_SESSION	= BIT(0),
};

struct tpm2_hash {
	unsigned int crypto_id;
	unsigned int tpm_id;
};

static inline u32 tpm2_rc_value(u32 rc)
{
	return (rc & BIT(7)) ? rc & 0xff : rc;
}

#endif
