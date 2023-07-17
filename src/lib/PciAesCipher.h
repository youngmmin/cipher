/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PciAesCipher
 *   Implementor        :       Jaehun
 *   Create Date        :       2013. 1. 16
 *   Description        :      
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCI_AES_CIPHER_H
#define PCI_AES_CIPHER_H

#include "PciBlockCipher.h"

class PciAesCipher : public PciBlockCipher {
  private:
	static const dgt_sint32	 AES_MAXNR = 14;

	typedef struct {
		dgt_uint32	rd_key[4 *(AES_MAXNR + 1)];
		dgt_sint32	rounds;
	} AES_KEY;

	dgt_uint8		KeySetEncFlag;
	dgt_uint8		KeySetDecFlag;
	AES_KEY			AesEncKey;
	AES_KEY			AesDecKey;

	dgt_sint32 setEncryptKey();
	dgt_sint32 setDecryptKey();

	virtual dgt_sint32	initializeContext();
	virtual dgt_sint32	encryptBlock(dgt_uint8* in,dgt_uint8* out);
	virtual dgt_sint32	decryptBlock(dgt_uint8* in,dgt_uint8* out);
  protected:
  public:
  	PciAesCipher();
	virtual ~PciAesCipher();
};


#endif
