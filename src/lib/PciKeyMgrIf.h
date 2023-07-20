/*******************************************************************
 *   File Type          :       interface class declaration
 *   Classes            :       PciKeyMgrIf
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 10. 10
 *   Description        :       petra cipher Key Managing Module interface
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCI_KEY_MGR_IF_H
#define PCI_KEY_MGR_IF_H

#include "DgcObject.h"

static const dgt_sint32 PCC_ERR_KMGR_WEAK_PASSWORD = -30601;
static const dgt_sint32 PCC_ERR_KMGR_WRONG_PASSWORD = -30602;
static const dgt_sint32 PCC_ERR_KMGR_NO_KEY_STASH = -30603;
static const dgt_sint32 PCC_ERR_KMGR_KEY_OPENED = -30604;
static const dgt_sint32 PCC_ERR_KMGR_KEY_NOT_OPEN = -30605;
static const dgt_sint32 PCC_ERR_KMGR_KEY_OVERFLOW = -30606;
static const dgt_sint32 PCC_ERR_KMGR_INVALID_INPUT_PARAM = -30607;
static const dgt_sint32 PCC_ERR_KMGR_KEY_STASH_SET_ALREADY = -30609;
static const dgt_sint32 PCC_ERR_KMGR_CORRUPTED_KEY_STASH = -30610;
static const dgt_sint32 PCC_ERR_NOT_SUPPORT_HSM = -30611;

static const dgt_uint32 PCC_MAX_KEY_SET_LENGTH = 2048;
static const dgt_uint32 PCC_MAX_EKEY_SET_LENGTH =
    PCC_MAX_KEY_SET_LENGTH + 4;  // 4 is the length of encryption trailer
static const dgt_uint32 PCC_KEY_SET_SIG_LENGTH = 32;
typedef struct {
    dgt_uint8 open_status;
    dgt_uint8 key_set_signature[PCC_KEY_SET_SIG_LENGTH];
    dgt_uint8 key_set[PCC_MAX_EKEY_SET_LENGTH];
} PCT_KEY_STASH;

dgt_sint32 PCI_PBKDF2(const dgt_schar* pw, const dgt_uint8* salt,
                      dgt_uint32 salt_len, dgt_uint8* mk, dgt_uint32* mk_len);

dgt_sint32 PCI_createKey(const dgt_schar* pw, dgt_void* thread_ptr,
                         dgt_schar* smk, dgt_uint32* smk_len, dgt_schar* seks,
                         dgt_uint32* seks_len, dgt_schar* sks,
                         dgt_uint32* sks_len, dgt_sint32 hsm_mode = 0,
                         const dgt_schar* hsm_password = 0);

dgt_sint32 PCI_checkPassword(const dgt_schar* pw, dgt_schar* smk,
                             dgt_uint32 smk_len, dgt_schar* seks,
                             dgt_uint32 seks_len, dgt_schar* sks,
                             dgt_uint32 sks_len, dgt_sint32 hsm_mode = 0,
                             const dgt_schar* hsm_password = 0);

dgt_sint32 PCI_changePassword(const dgt_schar* old_pw, const dgt_schar* new_pw,
                              dgt_schar* smk, dgt_uint32 smk_len,
                              dgt_schar* seks, dgt_uint32 seks_len,
                              dgt_schar* sks, dgt_uint32 sks_len,
                              dgt_sint32 hsm_mode = 0,
                              const dgt_schar* hsm_password = 0);

dgt_sint32 PCI_setKeyStash(PCT_KEY_STASH* key_stash);

dgt_sint32 PCI_getKeyStash(PCT_KEY_STASH** key_stash);

dgt_sint32 PCI_openKey(const dgt_schar* pw, dgt_schar* smk, dgt_uint32 smk_len,
                       dgt_schar* seks, dgt_uint32 seks_len, dgt_schar* sks,
                       dgt_uint32 sks_len, dgt_sint32 hsm_mode = 0,
                       const dgt_schar* hsm_password = 0);

dgt_sint32 PCI_closeKey(const dgt_schar* pw, dgt_schar* smk, dgt_uint32 smk_len,
                        dgt_schar* seks, dgt_uint32 seks_len, dgt_schar* sks,
                        dgt_uint32 sks_len, dgt_sint32 hsm_mode = 0,
                        const dgt_schar* hsm_password = 0);

dgt_sint32 PCI_getEncryptKey(dgt_uint32 key_idx, dgt_uint32 key_len,
                             dgt_uint8* key_buffer);

const dgt_schar* PCI_getKmgrErrMsg();

#if 0
dgt_uint32 PCI_dumpKeyStash(dgt_uint8* dbuf);
#endif

#endif
