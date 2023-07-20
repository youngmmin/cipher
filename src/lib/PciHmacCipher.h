/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PciHmacCipher
 *   Implementor        :       ihjin
 *   Create Date        :       2018. 10. 18
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------
2018.10.18 enhancement: source code refactoring
********************************************************************/
#ifndef PCI_HMAC_CIPHER_H
#define PCI_HMAC_CIPHER_H

#include "PciCipher.h"
#include "PciHmac.h"

class PciHmacCipher : public PciCipher {
   private:
    virtual dgt_sint32 initializeContext();

    inline dgt_sint32 encryptECB(dgt_uint8* ibuf, dgt_uint32 len,
                                 dgt_uint8* obuf, dgt_uint32* olen) {
        if (KeyBits == 160) {
            if (KeySetFlag) {
                PCI_HMAC(EVP_sha1(), Key, KeyBits / 8, ibuf, len, obuf, olen);
            }
            *olen = PCI_HMAC_SHA1_DIGEST_SIZE;
        } else if (KeyBits == 256) {
            if (KeySetFlag) {
                PCI_HMAC(EVP_sha256(), Key, KeyBits / 8, ibuf, len, obuf, olen);
            }
            *olen = PCI_HMAC_SHA256_DIGEST_SIZE;
        }
        return 0;
    }

   protected:
   public:
    PciHmacCipher();
    virtual ~PciHmacCipher();
    virtual dgt_sint32 encrypt(dgt_uint8* ibuf, dgt_uint32 len, dgt_uint8* obuf,
                               dgt_uint32* olen);
};

#endif
