/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PciLeaCipher
 *   Implementor        :       shson
 *   Create Date        :       2019. 07. 17
 *   Description        :      
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCI_LEA_CIPHER_H
#define PCI_LEA_CIPHER_H

#include "PciBlockCipher.h"

typedef struct lea_key_st
{
	    unsigned int rk[192];
		    unsigned int round;
} LEA_KEY;


class PciLeaCipher : public PciBlockCipher {
  private:
	  LEA_KEY LeaKey;

	dgt_void PciLeaKeyGeneric(LEA_KEY *key, const unsigned char *mk, unsigned int mk_len);
        virtual dgt_sint32      initializeContext();
        virtual dgt_sint32      encryptBlock(dgt_uint8* iblock,dgt_uint8* oblock);
        virtual dgt_sint32      decryptBlock(dgt_uint8* iblock,dgt_uint8* oblock);
  protected:
  public:
  	PciLeaCipher();
	virtual ~PciLeaCipher();
};

#endif
