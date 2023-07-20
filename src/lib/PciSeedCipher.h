/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PciSeedCipher
 *   Implementor        :       mwpark
 *   Create Date        :       2015. 1. 20
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCI_SEED_CIPHER_H
#define PCI_SEED_CIPHER_H

#include "PciBlockCipher.h"

class PciSeedCipher : public PciBlockCipher {
   private:
    void SeedEncRoundKey(dgt_uint32* pdwRoundKey, dgt_uint8* pbUserKey);

    virtual dgt_sint32 initializeContext();
    virtual dgt_sint32 encryptBlock(dgt_uint8* iblock, dgt_uint8* oblock);
    virtual dgt_sint32 decryptBlock(dgt_uint8* iblock, dgt_uint8* oblock);

   protected:
    dgt_uint32 Schedule[32];

   public:
    PciSeedCipher();
    virtual ~PciSeedCipher();
};

#endif
