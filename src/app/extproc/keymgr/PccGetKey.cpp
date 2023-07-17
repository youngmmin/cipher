/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccGetKey
 *   Implementor        :       mwpark
 *   Create Date        :       2014. 07. 30
 *   Description        :       get key
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PciKeyMgrIf.h"
#include "PccGetKey.h"
#include "PccTableTypes.h"
#include "DgcDbProcess.h"

PccGetKey::PccGetKey(const dgt_schar *name)
	: DgcExtProcedure(name)
{
}

PccGetKey::~PccGetKey()
{
}

DgcExtProcedure *PccGetKey::clone()
{
	return new PccGetKey(procName());
}

static const dgt_uint8 PCI_PIVS[64] = // Predefined Initial Vector seed
	{123, 8, 94, 71, 230, 9, 12, 70, 95, 71,
	 84, 84, 3, 78, 5, 63, 4, 83, 123, 95,
	 47, 56, 91, 34, 123, 46, 73, 214, 38, 24,
	 1, 239, 76, 237, 8, 39, 81, 80, 238, 90,
	 81, 3, 123, 89, 74, 1, 239, 81, 230, 67,
	 51, 236, 51, 59, 238, 74, 61, 92, 37, 84,
	 125, 180, 36, 237};
static inline dgt_uint8 *get_iv(dgt_uint8 iv_type)
{
	static dgt_uint8 *wjsdmswjd = 0;
	if (!wjsdmswjd)
	{
		wjsdmswjd = new dgt_uint8[64];
		memcpy(wjsdmswjd, PCI_PIVS, 64);
		for (dgt_uint8 i = 0; i < 64; i++)
			if (wjsdmswjd[i] < 100)
				wjsdmswjd[i] += wjsdmswjd[i] & 0xaf % 17;
			else
				wjsdmswjd[i] -= wjsdmswjd[i] & 0xba % 21;
	}
	return (wjsdmswjd + iv_type);
}

#include "PccExternalKey.h"
#include "PccExternalIV.h"

dgt_sint32 PccGetKey::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0)
	{
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR, new DgcError(SPOS, "invalid parameter")), -1);
	}
	dgt_schar *pwd = (dgt_schar *)BindRows->getColPtr(1);
	dgt_sint64 key_id = *(dgt_sint64 *)BindRows->getColPtr(2);
	ATHROWnR(DgcError(SPOS, "getColPtr failed"), -1);

	dgt_sys_param *param;
	dgt_sint32 hsm_mode = 0;
	dgt_schar hsm_password[128];
	memset(hsm_password, 0, 128);

	if ((param = DG_PARAM("USE_HSM_FLAG")) == 0)
		delete EXCEPTnC;
	else
	{
		if (param->val_number == 1)
		{
			hsm_mode = 1;
			if ((param = DG_PARAM("HSM_PASSWORD")) == 0)
				delete EXCEPTnC;
			else
			{
				strncpy(hsm_password, param->val_string, strlen(param->val_string));
			}
		}
	}

	//
	// check master key`s password
	//
	DgcTableSegment *tab = (DgcTableSegment *)Database->pdb()->segMgr()->getTable("PCT_KEY");
	if (tab == 0)
	{
		ATHROWnR(DgcError(SPOS, "getTable[PCT_KEY] failed"), -1);
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR, new DgcError(SPOS, "Table[PCT_KEY] not found")), -1);
	}
	tab->unlockShare();
	DgcRowRef key_rows(tab);
	if (key_rows.next())
	{
		pct_type_key *key_row = (pct_type_key *)key_rows.data();
		dgt_sint32 rtn = 0;
		if ((rtn = PCI_checkPassword(pwd, key_row->smk, strlen(key_row->smk), key_row->seks, strlen(key_row->seks),
									 key_row->sks, strlen(key_row->sks), hsm_mode, hsm_password)) < 0)
		{
			THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR, new DgcError(SPOS, "%d:%s", rtn, PCI_getKmgrErrMsg())), -1);
		}
	}

	//
	// get encrypt key info
	//
	dgt_schar sql_text[512];
	dg_sprintf(sql_text,
			   "select * from pct_encrypt_key where key_id=%lld", key_id);
	DgcSqlStmt *sql_stmt = Database->getStmt(Session, sql_text, strlen(sql_text));
	DgcExcept *e = 0;
	if (sql_stmt == 0 || sql_stmt->execute() < 0)
	{
		e = EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e, DgcError(SPOS, "execute[%lld] failed.", key_id), -1);
	}
	dgt_uint8 *tmp_row;
	if ((tmp_row = sql_stmt->fetch()) == 0)
	{
		e = EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e, DgcError(SPOS, "fetch[%lld] failed", key_id), -1);
	}
	pct_type_encrypt_key enc_key;
	memcpy(&enc_key, tmp_row, sizeof(enc_key));
	delete sql_stmt;

	//
	// get encrypt key
	//
	dgt_uint8 key[64];
	memset(key, 0, 64);
	dgt_sint32 rtn = 0;
	if (enc_key.key_no >= 10000)
	{
		//
		// external key
		//
		dg_sprintf(sql_text, "select * from pct_ext_key where key_no = %u", enc_key.key_no);
		DgcSqlStmt *sql_stmt = Database->getStmt(Session, sql_text, strlen(sql_text));
		DgcExcept *e = 0;
		if (sql_stmt == 0 || sql_stmt->execute() < 0)
		{
			e = EXCEPTnC;
			delete sql_stmt;
			RTHROWnR(e, DgcError(SPOS, "execute[%lld] failed.", key_id), -1);
		}
		pct_type_ext_key *ext_key;
		if ((ext_key = (pct_type_ext_key *)sql_stmt->fetch()))
		{
			PccExternalKey ek;
			ek.getKey(ext_key->key_no, ext_key->sek, ext_key->seks, enc_key.key_size / 8, key);
		}
		e = EXCEPTnC;
		delete sql_stmt;
		if (e)
		{
			RTHROWnR(e, DgcError(SPOS, "fetch external key_no[%u] failed", enc_key.key_no), -1);
		}
	}
	else
	{
		//
		// internal key
		//
		if ((rtn = PCI_getEncryptKey(enc_key.key_no, enc_key.key_size / 8, key)) < 0)
		{
			THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
								 new DgcError(SPOS, "getEncryptKey[%lld] failed due to %d:%s", key_id, rtn, PCI_getKmgrErrMsg())),
					-1);
		}
	}
	dgt_uint8 iv[64];
	memset(iv, 0, 64);
	if (enc_key.iv_type > 0 && enc_key.iv_type <= 10)
	{
		//
		// internal iv
		//
		memcpy(iv, get_iv(enc_key.iv_type), 16);
	}
	else if (enc_key.iv_type > 10)
	{
		//
		// external iv
		// The "IV_TYPE" column in the "PCT_ENCRYPT_KEY" table is identical to the "IV_NO" value in the "PCT_EXT_IV" table.
		//
		dg_sprintf(sql_text, "select * from pct_ext_iv where iv_no = %u", enc_key.iv_type);
		DgcSqlStmt *sql_stmt = Database->getStmt(Session, sql_text, strlen(sql_text));
		DgcExcept *e = 0;
		if (sql_stmt == 0 || sql_stmt->execute() < 0)
		{
			e = EXCEPTnC;
			delete sql_stmt;
			RTHROWnR(e, DgcError(SPOS, "execute[%lld] failed.", key_id), -1);
		}
		pct_type_ext_iv *ext_iv;
		if ((ext_iv = (pct_type_ext_iv *)sql_stmt->fetch()))
		{
			PccExternalIV eiv;
			eiv.getIV(ext_iv->iv_no, ext_iv->seiv, ext_iv->seivs, 16, iv);
		}
		e = EXCEPTnC;
		delete sql_stmt;
		if (e)
		{
			RTHROWnR(e, DgcError(SPOS, "fetch external iv_no[%u] failed", enc_key.iv_type), -1);
		}
	}

	ReturnRows->reset();
	ReturnRows->add();
	ReturnRows->next();
	memcpy(ReturnRows->data(), key, 64);
	ReturnRows->add();
	ReturnRows->next();
	memcpy(ReturnRows->data(), iv, 64);
	ReturnRows->rewind();
	return 0;
}
