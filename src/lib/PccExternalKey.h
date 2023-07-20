/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccExternalKey
 *   Implementor        :       chchung
 *   Create Date        :       2014. 8. 2
 *   Description        :       external key
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_EXTERNAL_KEY_H
#define PCC_EXTERNAL_KEY_H

#include "PciCryptoIf.h"
#include "PciKeyMgrIf.h"

class PccExternalKey {
   private:
    static const dgt_uint16 PARENT_KEY_SIZE = 256;
    static const dgt_sint64 MAX_EXT_KEY_LEN = 512;

    PCI_Context EncContext;
    PCI_Context HashContext;
    dgt_uint8 ExtKey[MAX_EXT_KEY_LEN];
    dgt_uint32 ExtKeyLen;
    dgt_uint8 ParentKey[64];

    inline dgt_sint32 initContext(dgt_uint16 key_no) throw(DgcExcept) {
        dgt_sint32 rtn = 0;
        memset(ParentKey, 0, 64);
        key_no = key_no % 1000;
        if ((rtn = PCI_getEncryptKey(key_no, PARENT_KEY_SIZE / 8, ParentKey)) <
            0) {
            THROWnR(
                DgcPciExcept(
                    DGC_EC_PCI_ERR,
                    new DgcError(SPOS, "PCI_getEncryptKey[%u] failed, %d:%s",
                                 key_no, rtn, PCI_getKmgrErrMsg())),
                -1);
        }
        if ((rtn = PCI_initContext(&EncContext, ParentKey, PARENT_KEY_SIZE,
                                   PCI_CIPHER_AES, PCI_EMODE_CBC, PCI_IVT_PIV1,
                                   0, 1, 1)) < 0) {
            THROWnR(
                DgcPciExcept(DGC_EC_PCI_ERR,
                             new DgcError(SPOS, "PCI_initContext failed, %d:%s",
                                          rtn, PCI_getKmgrErrMsg())),
                -1);
        }
        if ((rtn = PCI_initContext(&HashContext, 0, PARENT_KEY_SIZE,
                                   PCI_CIPHER_SHA, 0, PCI_IVT_PIV1, 0, 1, 1)) <
            0) {
            THROWnR(
                DgcPciExcept(DGC_EC_PCI_ERR,
                             new DgcError(SPOS, "PCI_initContext failed, %d:%s",
                                          rtn, PCI_getKmgrErrMsg())),
                -1);
        }
        return rtn;
    }

   protected:
   public:
    PccExternalKey();
    virtual ~PccExternalKey();

    dgt_sint32 createKey(const dgt_schar* str_key, dgt_uint16 format_no,
                         dgt_sint64 key_id, dgt_uint16* key_no, dgt_schar* sek,
                         dgt_uint32* sek_len, dgt_schar* seks,
                         dgt_uint32* seks_len) throw(DgcExcept);

    dgt_sint32 checkKey(dgt_uint16 key_no, const dgt_schar* sek,
                        const dgt_schar* seks) throw(DgcExcept);

    dgt_sint32 getKey(dgt_uint16 key_no, const dgt_schar* sek,
                      const dgt_schar* seks, dgt_uint32 key_len,
                      dgt_uint8* key_buffer) throw(DgcExcept);
};

#endif
