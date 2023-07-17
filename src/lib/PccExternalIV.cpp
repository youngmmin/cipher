/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccExternalIV
 *   Implementor        :       chchung
 *   Create Date        :       2014. 8. 3
 *   Description        :       external iv
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccExternalIV.h"
#include "DgcBase64.h"
#include "DgcWorker.h"

PccExternalIV::PccExternalIV()
{
}

PccExternalIV::~PccExternalIV()
{
}

dgt_sint32 PccExternalIV::createIV(
	const dgt_schar* str_iv,
	dgt_uint16 format_no,
	dgt_sint64 iv_id,
	dgt_uint8* iv_no,
	dgt_schar* seiv,
	dgt_uint32* seiv_len,
	dgt_schar* seivs,
	dgt_uint32* seivs_len) throw(DgcExcept)
{
#if 0
DgcWorker::PLOG.tprintf(0,"createIV => str_iv[%s],format_no[%u],iv_id[%lld]\n",str_iv,format_no,iv_id);
#endif
	//
	// extract external iv
	//
	dgt_sint32 str_iv_len = strlen(str_iv);
	if (format_no == 128) {
                memcpy(ExtIV+1, str_iv, ExtIVLen=str_iv_len);
	} else if (format_no == 64) {
		if ((ExtIVLen=DgcBase64::decode2(str_iv, str_iv_len, ExtIV+1, MAX_EXT_IV_LEN-1)) < 0) {
			THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,new DgcError(SPOS,"invalid base64 format")),-1);
		}
	} else if (format_no == 16) {
		if ((ExtIVLen=DgcBase16::decode(str_iv, str_iv_len, ExtIV+1, MAX_EXT_IV_LEN-1)) < 0) {
			THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,new DgcError(SPOS,"invalid base16 format")),-1);
		}
	} else {
		THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,new DgcError(SPOS,"format should be 16, 64, or 128")),-1);
	}
	*iv_no = (dgt_uint8)(iv_id % 246) + 10;
	*ExtIV = *iv_no;
	ExtIVLen += 1;
#if 1
dgt_schar ext_in_hex[1025];
DgcBase16::encode(ExtIV,ExtIVLen,ext_in_hex,1024);
DgcWorker::PLOG.tprintf(0,"createIV => ExtIV[%s] iv_no[%u]\n",ext_in_hex,*iv_no);
#endif
	//
	// encrypt external iv
	//
	if (initContext(*iv_no)) {
		ATHROWnR(DgcError(SPOS,"initContext failed"),-1);
	}
	dgt_sint32 rtn;
	if ((rtn=PCI_encrypt(&EncContext, ExtIV, ExtIVLen, (dgt_uint8*)seiv, seiv_len)) < 0) {
		THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,
			new DgcError(SPOS,"PCI_encrypt failed, %d:%s", rtn, PCI_getKmgrErrMsg())),-1);
        }
	if ((rtn=PCI_encrypt(&HashContext, ExtIV, ExtIVLen, (dgt_uint8*)seivs, seivs_len)) < 0) {
		THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,
			new DgcError(SPOS,"PCI_encrypt failed, %d:%s", rtn, PCI_getKmgrErrMsg())),-1);
        }
	return 0;
}

dgt_sint32 PccExternalIV::checkIV(dgt_uint8 iv_no,const dgt_schar* seiv,const dgt_schar* seivs) throw(DgcExcept)
{
	//
	// decrypt the external iv
	//
	if (initContext(iv_no)) {
		ATHROWnR(DgcError(SPOS,"initContext failed"),-1);
	}
	ExtIVLen = MAX_EXT_IV_LEN;
	dgt_sint32 rtn;
	if ((rtn=PCI_decrypt(&EncContext,(dgt_uint8*)seiv,strlen(seiv),ExtIV,&ExtIVLen)) < 0) {
		THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,
			new DgcError(SPOS,"PCI_encrypt failed, %d:%s", rtn, PCI_getKmgrErrMsg())),-1);
        }
#if 1
dgt_schar ext_in_hex[1025];
DgcBase16::encode(ExtIV,ExtIVLen,ext_in_hex,1024);
// DgcWorker::PLOG.tprintf(0,"checkIV => ExtIV[%s] \n",ext_in_hex);
#endif
	//
	// check the iv number
	//
	dgt_uint8 enc_iv_no = 0;
	enc_iv_no = *ExtIV;
	if (iv_no != enc_iv_no) {
		THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,new DgcError(SPOS,"iv_no[%u] mismatch with saved iv_no[%u]",iv_no,enc_iv_no)),-1);
	}
	//
	// check the signature
	//
	dgt_schar tmp_seivs[513];
	dgt_uint32 tmp_seivs_len = 512;
	memset(tmp_seivs,0,513);
	if ((rtn=PCI_encrypt(&HashContext,ExtIV,ExtIVLen,(dgt_uint8*)tmp_seivs,&tmp_seivs_len)) < 0) {
		THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,
			new DgcError(SPOS,"PCI_encrypt failed, %d:%s", rtn, PCI_getKmgrErrMsg())),-1);
	}
	if (strncmp(seivs,tmp_seivs,tmp_seivs_len)) {
		THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,new DgcError(SPOS,"signature validation failed.")),-1);
	}
	return 0;
}

dgt_sint32 PccExternalIV::getIV(
	dgt_uint8 iv_no,
	const dgt_schar* seiv,
	const dgt_schar* seivs,
	dgt_uint16 iv_len,
	dgt_uint8* iv_buffer) throw(DgcExcept)
{
	if (checkIV(iv_no,seiv,seivs)) {
		ATHROWnR(DgcError(SPOS,"checkIV[%u] failed",iv_no),-1);
	}
	if (iv_len > (ExtIVLen-1)) {
		THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,new DgcError(SPOS,"request iv size[%u] is too big for [%u]",iv_len,ExtIVLen-1)),-1);
	}
	memcpy(iv_buffer,ExtIV+1,iv_len);
	return 0;
}
