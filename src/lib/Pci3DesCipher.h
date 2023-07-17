/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       Pci3DesCipher
 *   Implementor        :       mwpark
 *   Create Date        :       2015. 1. 20
 *   Description        :      
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCI_3DES_CIPHER
#define PCI_3DES_CIPHER

#include "PciBlockCipher.h"

#ifndef PCI_DES_LONG
#ifdef DGC_64_BITS
#define PCI_DES_LONG unsigned int
#else /* Not a 64 bit machine */
#define PCI_DES_LONG unsigned long
#endif
#endif

typedef unsigned char pci_des_cblock[8];
typedef struct pci_des_ks_struct
{
	pci_des_cblock  block;
} pci_des_key_schedule[16];

class Pci3DesCipher : public PciBlockCipher {
  private:
	dgt_sint32 desSetKey(const dgt_schar* key,pci_des_key_schedule schedule);
	dgt_void desEncrypt2(PCI_DES_LONG* data,pci_des_key_schedule ks,dgt_sint32 encrypt);

        virtual dgt_sint32      initializeContext();
        virtual dgt_sint32      encryptBlock(dgt_uint8* iblock,dgt_uint8* oblock);
        virtual dgt_sint32      decryptBlock(dgt_uint8* iblock,dgt_uint8* oblock);
  protected:
	pci_des_key_schedule	Schedule1;          // des key schedule
	pci_des_key_schedule	Schedule2;          // des key schedule
	pci_des_key_schedule	Schedule3;          // des key schedule
  public:
	Pci3DesCipher();
	virtual ~Pci3DesCipher(); 
};


#endif
