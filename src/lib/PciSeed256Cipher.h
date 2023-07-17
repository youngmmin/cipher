/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PciSeed256Cipher
 *   Implementor        :       mwpark
 *   Create Date        :       2016. 6. 13
 *   Description        :      
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCI_SEED256_CIPHER_H
#define PCI_SEED256_CIPHER_H

#include "PciBlockCipher.h"

class PciSeed256Cipher : public PciBlockCipher {
  private:
	void SeedEncRoundKey(dgt_uint32 *pdwRoundKey,dgt_uint8 *pbUserKey);

        virtual dgt_sint32      initializeContext();
        virtual dgt_sint32      encryptBlock(dgt_uint8* iblock,dgt_uint8* oblock);
        virtual dgt_sint32      decryptBlock(dgt_uint8* iblock,dgt_uint8* oblock);
  protected:
	dgt_uint32		Schedule[48];
  public:
  	PciSeed256Cipher();
	virtual ~PciSeed256Cipher();
};

#endif
