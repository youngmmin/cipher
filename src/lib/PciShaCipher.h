/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PciShaCipher
 *   Implementor        :       Jaehun
 *   Create Date        :       2015. 1. 15
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------
2015.8.11 enhancement: add padding
********************************************************************/
#ifndef PCI_SHA_CIPHER_H
#define PCI_SHA_CIPHER_H

#include "PciCipher.h"
#include "PciSha2.h"

class PciShaCipher : public PciCipher {
  private:
	virtual dgt_sint32 initializeContext();

	inline dgt_sint32 encryptECB(dgt_uint8* ibuf,dgt_uint32 len,dgt_uint8* obuf,dgt_uint32* olen)
	{
		if(KeyBits == 256) {
			pci_sha256_ctx  md_ctx;
			pci_sha256_init(&md_ctx);
                        pci_sha256_update(&md_ctx, ibuf, len);
			pci_sha256_final(&md_ctx, obuf);
			*olen = PCI_SHA256_DIGEST_SIZE;
		} else if(KeyBits == 384) {
			pci_sha384_ctx  md_ctx;
			pci_sha384_init(&md_ctx);
                        pci_sha384_update(&md_ctx, ibuf, len);
			pci_sha384_final(&md_ctx, obuf);
			*olen = PCI_SHA384_DIGEST_SIZE;
		} else if(KeyBits == 512) {
			pci_sha512_ctx  md_ctx;
			pci_sha512_init(&md_ctx);
                        pci_sha512_update(&md_ctx, ibuf, len);
			pci_sha512_final(&md_ctx, obuf);
			*olen = PCI_SHA512_DIGEST_SIZE;
		}
		return 0;
	}

	inline dgt_sint32 encryptCBC(dgt_uint8* ibuf,dgt_uint32 len,dgt_uint8* obuf,dgt_uint32* olen)
	{
		if(KeyBits == 256) {
			pci_sha256_ctx  md_ctx;
			pci_sha256_init(&md_ctx);
			if (KeySetFlag) pci_sha256_update(&md_ctx, Key, *olen);
                        pci_sha256_update(&md_ctx, ibuf, len);
			if (IV) pci_sha256_update(&md_ctx, IV, 32);
			pci_sha256_final(&md_ctx, obuf);
			*olen = PCI_SHA256_DIGEST_SIZE;
		} else if(KeyBits == 384) {
			pci_sha384_ctx  md_ctx;
			pci_sha384_init(&md_ctx);
			if (KeySetFlag) pci_sha384_update(&md_ctx, Key, *olen);
                        pci_sha384_update(&md_ctx, ibuf, len);
			if (IV) pci_sha384_update(&md_ctx, IV, 32);
			pci_sha384_final(&md_ctx, obuf);
			*olen = PCI_SHA384_DIGEST_SIZE;
		} else if(KeyBits == 512) {
			pci_sha512_ctx  md_ctx;
			pci_sha512_init(&md_ctx);
			if (KeySetFlag) pci_sha512_update(&md_ctx, Key, *olen);
                        pci_sha512_update(&md_ctx, ibuf, len);
			if (IV) pci_sha512_update(&md_ctx, IV, 32);
			pci_sha512_final(&md_ctx, obuf);
			*olen = PCI_SHA512_DIGEST_SIZE;
		}
		return 0;
	}
  protected:
  public:
        PciShaCipher();
        virtual ~PciShaCipher();
	virtual dgt_sint32 encrypt(dgt_uint8* ibuf,dgt_uint32 len,dgt_uint8* obuf,dgt_uint32* olen);
};

#endif
