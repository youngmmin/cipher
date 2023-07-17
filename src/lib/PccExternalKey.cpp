/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccExternalKey
 *   Implementor        :       chchung
 *   Create Date        :       2014. 8. 3
 *   Description        :       external key
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccExternalKey.h"
#include "DgcBase64.h"
#include "DgcWorker.h"

PccExternalKey::PccExternalKey()
{
}

PccExternalKey::~PccExternalKey()
{
}

dgt_sint32 PccExternalKey::createKey(
	const dgt_schar* str_key,
	dgt_uint16 format_no,
	dgt_sint64 key_id,
	dgt_uint16* key_no,
	dgt_schar* sek,
	dgt_uint32* sek_len,
	dgt_schar* seks,
	dgt_uint32* seks_len) throw(DgcExcept)
{
#if 0
DgcWorker::PLOG.tprintf(0,"createKey => str_key[%s],format_no[%u],key_id[%lld]\n",str_key,format_no,key_id);
#endif
	//
	// extract external key
	//
	dgt_sint32 str_key_len = strlen(str_key);
	if (format_no == 128) {
                memcpy(ExtKey+2, str_key, ExtKeyLen=str_key_len);
	} else if (format_no == 64) {
		if ((ExtKeyLen=DgcBase64::decode2(str_key, str_key_len, ExtKey+2, MAX_EXT_KEY_LEN-2)) < 0) {
			THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,new DgcError(SPOS,"invalid base64 format")),-1);
		}
	} else if (format_no == 16) {
		if ((ExtKeyLen=DgcBase16::decode(str_key, str_key_len, ExtKey+2, MAX_EXT_KEY_LEN-2)) < 0) {
			THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,new DgcError(SPOS,"invalid base16 format")),-1);
		}
	} else {
		THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,new DgcError(SPOS,"format should be 16, 64, or 128")),-1);
	}
	*key_no = (dgt_uint16)(key_id % 50000) + 10000;
	mcp2(ExtKey,(dgt_uint8*)key_no);
	ExtKeyLen += 2;
#if 0
dgt_schar ext_in_hex[1025];
DgcBase16::encode(ExtKey,ExtKeyLen,ext_in_hex,1024);
DgcWorker::PLOG.tprintf(0,"createKey => ExtKey[%s] key_no[%u]\n",ext_in_hex,*key_no);
#endif
	//
	// encrypt external key
	//
	if (initContext(*key_no)) {
		ATHROWnR(DgcError(SPOS,"initContext failed"),-1);
	}
	dgt_sint32 rtn;
	if ((rtn=PCI_encrypt(&EncContext, ExtKey, ExtKeyLen, (dgt_uint8*)sek, sek_len)) < 0) {
		THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,
			new DgcError(SPOS,"PCI_encrypt failed, %d:%s", rtn, PCI_getKmgrErrMsg())),-1);
        }
	if ((rtn=PCI_encrypt(&HashContext, ExtKey, ExtKeyLen, (dgt_uint8*)seks, seks_len)) < 0) {
		THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,
			new DgcError(SPOS,"PCI_encrypt failed, %d:%s", rtn, PCI_getKmgrErrMsg())),-1);
        }
	return 0;
}

dgt_sint32 PccExternalKey::checkKey(dgt_uint16 key_no,const dgt_schar* sek,const dgt_schar* seks) throw(DgcExcept)
{
	//
	// decrypt the external key
	//
	if (initContext(key_no)) {
		ATHROWnR(DgcError(SPOS,"initContext failed"),-1);
	}
	ExtKeyLen = MAX_EXT_KEY_LEN;
	dgt_sint32 rtn;
	if ((rtn=PCI_decrypt(&EncContext,(dgt_uint8*)sek,strlen(sek),ExtKey,&ExtKeyLen)) < 0) {
		THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,
			new DgcError(SPOS,"PCI_encrypt failed, %d:%s", rtn, PCI_getKmgrErrMsg())),-1);
        }
#if 0
dgt_schar ext_in_hex[1025];
DgcBase16::encode(ExtKey,ExtKeyLen,ext_in_hex,1024);
DgcWorker::PLOG.tprintf(0,"checkKey => ExtKey[%s] \n",ext_in_hex);
#endif
	//
	// check the key number
	//
	dgt_uint16 enc_key_no = 0;
	mcp2((dgt_uint8*)&enc_key_no,ExtKey);
	if (key_no != enc_key_no) {
		THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,new DgcError(SPOS,"key_no[%u] mismatch with saved key_no[%u]",key_no,enc_key_no)),-1);
	}
	//
	// check the signature
	//
	dgt_schar tmp_seks[513];
	dgt_uint32 tmp_seks_len = 512;
	memset(tmp_seks,0,513);
	if ((rtn=PCI_encrypt(&HashContext,ExtKey,ExtKeyLen,(dgt_uint8*)tmp_seks,&tmp_seks_len)) < 0) {
		THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,
			new DgcError(SPOS,"PCI_encrypt failed, %d:%s", rtn, PCI_getKmgrErrMsg())),-1);
	}
	if (strncmp(seks,tmp_seks,tmp_seks_len)) {
		THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,new DgcError(SPOS,"signature validation failed.")),-1);
	}
	return 0;
}

dgt_sint32 PccExternalKey::getKey(
	dgt_uint16 key_no,
	const dgt_schar* sek,
	const dgt_schar* seks,
	dgt_uint32 key_len,
	dgt_uint8* key_buffer) throw(DgcExcept)
{
	if (checkKey(key_no,sek,seks)) {
		ATHROWnR(DgcError(SPOS,"checkKey[%u] failed",key_no),-1);
	}
#if 0
	if (key_len > (ExtKeyLen-2)) {
		THROWnR(DgcPciExcept(DGC_EC_PCI_ERR,new DgcError(SPOS,"request key size[%u] is too big for [%u]",key_len,ExtKeyLen-2)),-1);
	}
#endif
	memset(key_buffer,0,key_len);
#if 0
	memcpy(key_buffer,ExtKey+2,key_len);
#else
	memcpy(key_buffer,ExtKey+2,ExtKeyLen);
#endif
	return 0;
}
