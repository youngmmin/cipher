/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccExternalIV
 *   Implementor        :       chchung
 *   Create Date        :       2014. 8. 2
 *   Description        :       external iv
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_EXTERNAL_IV_H
#define PCC_EXTERNAL_IV_H

#include "PciCryptoIf.h"
#include "PciKeyMgrIf.h"

class PccExternalIV {
  private:
	static const dgt_uint16 PARENT_KEY_SIZE = 256;
	static const dgt_sint64 MAX_EXT_IV_LEN = 512;

	PCI_Context	EncContext;
	PCI_Context	HashContext;
	dgt_uint8	ExtIV[MAX_EXT_IV_LEN];
	dgt_uint32	ExtIVLen;
	dgt_uint8	ParentKey[64];

	inline dgt_sint32 initContext(dgt_uint8 iv_no) throw(DgcExcept)
	{
		dgt_sint32 rtn = 0;
		memset(ParentKey,0,64);
		if ((rtn=PCI_getEncryptKey(iv_no,PARENT_KEY_SIZE/8,ParentKey)) < 0) {
			THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,
				new DgcError(SPOS,"PCI_getEncryptKey[%u] failed, %d:%s",iv_no,rtn,PCI_getKmgrErrMsg())),-1);
		}
		if ((rtn=PCI_initContext(&EncContext,ParentKey,PARENT_KEY_SIZE,PCI_CIPHER_AES,PCI_EMODE_CBC,PCI_IVT_PIV1,0,1,1)) < 0) {
			THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,
				new DgcError(SPOS,"PCI_initContext failed, %d:%s", rtn, PCI_getKmgrErrMsg())),-1);
		}
		if ((rtn=PCI_initContext(&HashContext,0,PARENT_KEY_SIZE,PCI_CIPHER_SHA,0,PCI_IVT_PIV1,0,1,1)) < 0) {
			THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,
				new DgcError(SPOS,"PCI_initContext failed, %d:%s", rtn, PCI_getKmgrErrMsg())),-1);
		}
		return rtn;
	}
  protected:
  public:
	PccExternalIV();
	virtual ~PccExternalIV();

	dgt_sint32 createIV(const dgt_schar* str_iv,dgt_uint16 format_no,dgt_sint64 iv_id,
	 	dgt_uint8* iv_no,dgt_schar* seiv,dgt_uint32* seiv_len,dgt_schar* seivs,dgt_uint32* seivs_len) throw(DgcExcept);

	dgt_sint32 checkIV(dgt_uint8 iv_no,const dgt_schar* seiv,const dgt_schar* seivs) throw(DgcExcept);

	dgt_sint32 getIV(dgt_uint8 iv_no,const dgt_schar* seiv,const dgt_schar* seivs,
			  dgt_uint16 iv_len,dgt_uint8* iv_buffer) throw(DgcExcept);
};

#endif
