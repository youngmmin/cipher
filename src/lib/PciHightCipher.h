/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PciHightCipher
 *   Implementor        :       ihjin
 *   Create Date        :       2019. 06. 07
 *   Description        :      
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCI_HIGHT_CIPHER_H
#define PCI_HIGHT_CIPHER_H

#include "PciBlockCipher.h"

class PciHightCipher : public PciBlockCipher {
  private:
	unsigned char HightKey[16];
	unsigned char RoundKey[136];

	dgt_void pciHightKeySched();
        virtual dgt_sint32      initializeContext();
        virtual dgt_sint32      encryptBlock(dgt_uint8* iblock,dgt_uint8* oblock);
        virtual dgt_sint32      decryptBlock(dgt_uint8* iblock,dgt_uint8* oblock);
  protected:
  public:
  	PciHightCipher();
	virtual ~PciHightCipher();
};

#endif
