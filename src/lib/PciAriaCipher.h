/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PciAriaCipher
 *   Implementor        :       mwpark
 *   Create Date        :       2015. 8. 05
 *   Description        :      
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCI_ARIA_CIPHER_H
#define PCI_ARIA_CIPHER_H

#include "PciBlockCipher.h"

typedef union {
        struct {
                int             key_len;
                unsigned char   round_key[16*17];
        } k32;
        struct {
                unsigned int    round_key1[4*17];
                unsigned int    round_key2[4*17];
                int             rounds;
                int             encrypt_flag;
        } k64;
} pct_aria_key;


class PciAriaCipher : public PciBlockCipher {
  private:
	static const dgt_sint8 KS_NO = 0;
	static const dgt_sint8 KS_ENC = 1;
	static const dgt_sint8 KS_DEC = 2;

	pct_aria_key	EncKey;
	pct_aria_key	DecKey;
	dgt_sint8	EncKeyStatus;
	dgt_sint8	DecKeyStatus;

        virtual dgt_sint32      initializeContext();
        virtual dgt_sint32      encryptBlock(dgt_uint8* iblock,dgt_uint8* oblock);
        virtual dgt_sint32      decryptBlock(dgt_uint8* iblock,dgt_uint8* oblock);
  protected:
  public:
	int PCI_ARIA_makeEncKey();
	int PCI_ARIA_makeDecKey();
  	PciAriaCipher();
	virtual ~PciAriaCipher();
};


#endif
