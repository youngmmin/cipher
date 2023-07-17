/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtGetVKeyPriv
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :       KRED get key statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtGetVKeyPriv.h"
#include "PciCryptoIf.h"
#include "DgcDbProcess.h"
#include "PccKredSessionPool.h"


PccKredStmtGetVKeyPriv::PccKredStmtGetVKeyPriv(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term)
	: PccKredStmt(pdb, session, stmt_term), NumRtnRows(0)
{
	SelectListDef = new DgcClass("select_list", 17);
	SelectListDef->addAttr(DGC_SB8, 0, "enc_col_id");
	SelectListDef->addAttr(DGC_SB8, 0, "key_id");
	SelectListDef->addAttr(DGC_UB4, 0, "max_col_len");
	SelectListDef->addAttr(DGC_UB4, 0, "dec_alt_threshold");
	SelectListDef->addAttr(DGC_UB4, 0, "dec_masking_threshold");
	SelectListDef->addAttr(DGC_UB1, 0, "enc_priv");
	SelectListDef->addAttr(DGC_UB1, 0, "dec_priv");
	SelectListDef->addAttr(DGC_UB1, 0, "enc_no_priv_alert");
	SelectListDef->addAttr(DGC_UB1, 0, "dec_no_priv_alert");
	SelectListDef->addAttr(DGC_UB1, 0, "auth_fail_enc_priv");
	SelectListDef->addAttr(DGC_UB1, 0, "auth_fail_dec_priv");
	SelectListDef->addAttr(DGC_UB1, 0, "enc_audit_flag");
	SelectListDef->addAttr(DGC_UB1, 0, "dec_audit_flag");
	SelectListDef->addAttr(DGC_UB1, 0, "col_type");
	SelectListDef->addAttr(DGC_UB1, 0, "ophuek_flag");
	SelectListDef->addAttr(DGC_UB1, 0, "multibyte_flag");
	SelectListDef->addAttr(DGC_ACHR, 12, "week_map");

	NameStr = 0;
}


PccKredStmtGetVKeyPriv::~PccKredStmtGetVKeyPriv()
{
	if (NameStr) delete NameStr;
}


dgt_sint32 PccKredStmtGetVKeyPriv::getEncColumn(dgt_sint64 virtual_key_id, dgt_uint64 user_sid, dgt_uint8 crypt_type) throw(DgcExcept)
{
	//
	// get virtual key
	//
	DgcMemRows      v_bind(1);
	v_bind.addAttr(DGC_SB8,0,"sb8_id");
	v_bind.reset();
	v_bind.add();
	v_bind.next();
	memcpy(v_bind.getColPtr(1),&virtual_key_id, sizeof(dgt_sint64));
	v_bind.rewind();

	dgt_schar	sql_text[256];
	dg_sprintf(sql_text,"select * from pvat_cipher_virtual_key where virtual_key_id=:1");
	DgcSqlStmt*	sql_stmt = DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text, strlen(sql_text));
	DgcExcept*	e = 0;
	if (sql_stmt == 0 || sql_stmt->execute(&v_bind, 0) < 0) {
		e = EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"virtual key execute[%lld] failed.",virtual_key_id),-1);
	}
	pvat_type_cipher_virtual_key*	virtual_key;
	if ((virtual_key=(pvat_type_cipher_virtual_key*)sql_stmt->fetch()) == 0) {
		e = EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"virtual key fetch[%lld] failed",virtual_key_id),-1);
	}

	if (virtual_key->crypt_type && virtual_key->crypt_type != crypt_type) return 10;

	//
	// check validation
	//
	dgt_uint16 str_time = 0, end_time = 0;
	dgt_schar time_map[6];
	struct tm res;
	struct tm* timeinfo;
	dgt_time ct = dgtime(&ct);
	time_t temp_ct = ct;
	timeinfo = localtime_r(&temp_ct, &res);
	if (virtual_key->valid_from && virtual_key->valid_to) {
		sprintf(time_map, "%u", virtual_key->access_hour_map);
		str_time = atoif(time_map + 1, 2);
		end_time = atoif(time_map + 3, 2);

		dgt_sint32 rtn = 0;
		if (ct < virtual_key->valid_from || ct > virtual_key->valid_to) rtn = 1;
		if (virtual_key->access_date_map[timeinfo->tm_wday] == '0') rtn = 2;
		if (str_time <= end_time
			&& (timeinfo->tm_hour < str_time || timeinfo->tm_hour >= end_time)) rtn = 3;
		if (str_time > end_time
			&& !((timeinfo->tm_hour >= str_time && timeinfo->tm_hour < 24)
					|| (timeinfo->tm_hour < end_time && timeinfo->tm_hour >= 0))) rtn = 3;
		if (rtn) {
			// no virtual key in validation date
			delete sql_stmt;
			return rtn;
		}
	}

	dgt_uint8 week_map = 0;
	if (virtual_key->access_date_map[0] == '1') week_map |= 128;
	if (virtual_key->access_date_map[1] == '1') week_map |= 64;
	if (virtual_key->access_date_map[2] == '1') week_map |= 32;
	if (virtual_key->access_date_map[3] == '1') week_map |= 16;
	if (virtual_key->access_date_map[4] == '1') week_map |= 8;
	if (virtual_key->access_date_map[5] == '1') week_map |= 4;
	if (virtual_key->access_date_map[6] == '1') week_map |= 2;
	PrivInfo.week_map[0] = week_map;
	PrivInfo.week_map[1] = str_time;  // start hour
	PrivInfo.week_map[2] = 0;		  // start min
	PrivInfo.week_map[3] = end_time;  // end hour
	PrivInfo.week_map[4] = 0;  // end min
	PrivInfo.week_map[5] = 0;  // contrary_flag

	PrivInfo.week_map[6] = week_map;
	PrivInfo.week_map[7] = str_time;  // start hour
	PrivInfo.week_map[8] = 0;		  // start min
	PrivInfo.week_map[9] = end_time;  // end hour
	PrivInfo.week_map[10] = 0;  // end min
	PrivInfo.week_map[11] = 0;  // contrary_flag

	//
	// check access ip
	//
	if (virtual_key->check_ip_flag) {
		pt_type_sess_user*	sess_user = PccKredSessionPool::getSessUser(user_sid);
		if (sess_user == 0) {
			ATHROWnR(DgcError(SPOS,"getSessUser[%lld] failed.",user_sid),-1);
		}
		if (strcmp(virtual_key->access_ip,sess_user->client_ip)) {
			delete sql_stmt;
			return 4;
		}
	}

	dgt_sint64 enc_col_id = virtual_key->enc_col_id;
	delete sql_stmt;
	sql_stmt = 0;

	//
	// get encrypt column
	//
    v_bind.reset();
    v_bind.add();
    v_bind.next();
    memcpy(v_bind.getColPtr(1),&enc_col_id, sizeof(dgt_sint64));
    v_bind.rewind();

    memset(sql_text,0,256);
	dg_sprintf(sql_text,"select * from pct_enc_column where enc_col_id=:1");
	sql_stmt = DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text, strlen(sql_text));
	e = 0;
	if (sql_stmt == 0 || sql_stmt->execute(&v_bind, 0) < 0) {
		e = EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"enc column execute[%lld] failed.",enc_col_id),-1);
	}
	pct_type_enc_column*	enc_column;
	if ((enc_column=(pct_type_enc_column*)sql_stmt->fetch()) == 0) {
		e = EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"enc column fetch[%lld] failed",enc_col_id),-1);
	}
	memcpy(&EncColumn,enc_column,sizeof(pct_type_enc_column));

	PrivInfo.enc_col_id = enc_col_id;
	PrivInfo.key_id = EncColumn.key_id;
	if (EncColumn.multi_byte_flag) PrivInfo.max_col_len = EncColumn.data_length * 3;
	else PrivInfo.max_col_len = EncColumn.data_length;
	if (strcasecmp(EncColumn.data_type,"NUMBER") == 0) PrivInfo.col_type = PCI_SRC_TYPE_NUM;
	else if (strcasecmp(EncColumn.data_type,"DATE") == 0) PrivInfo.col_type = PCI_SRC_TYPE_DATE;
	else if (strcasecmp(EncColumn.data_type,"TIMESTAMP") == 0) PrivInfo.col_type = PCI_SRC_TYPE_DATE;
	else if (strcasecmp(EncColumn.data_type,"RAW") == 0) PrivInfo.col_type = PCI_SRC_TYPE_RAW;
	else if (strcasecmp(EncColumn.data_type,"CHAR") == 0) PrivInfo.col_type = PCI_SRC_TYPE_CHAR;
	else if (strcasecmp(EncColumn.data_type,"NCHAR") == 0) PrivInfo.col_type = PCI_SRC_TYPE_CHAR;
	else PrivInfo.col_type = PCI_SRC_TYPE_VARCHAR;
	delete sql_stmt;
	PrivInfo.multibyte_flag = EncColumn.multi_byte_flag;
#if 1 // added by chchung 2013.9.22 for adding test mode
	if (EncColumn.curr_enc_step == 1) PrivInfo.ophuek_flag = 2;
#endif

	v_bind.rewind();
	sql_stmt = 0;
	memset(sql_text,0,256);
	dg_sprintf(sql_text,"select enc_col_id from pct_enc_index where enc_col_id=:1 and index_type =1");
	sql_stmt = DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text, strlen(sql_text));
	e = 0;
	if (sql_stmt == 0 || sql_stmt->execute(&v_bind, 0) < 0) {
		e = EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"execute[%lld] failed.",enc_col_id),-1);
	}
	dgt_uint8*      idx_ptr;
	dgt_sint64      idx_count=0;
	if ((idx_ptr=sql_stmt->fetch()) == 0) {
		e = EXCEPTnC;
		delete e;
	} else {
		memcpy(&idx_count,idx_ptr,sizeof(dgt_sint64));
	}

#if 1 // modified by chchung 2013.9.22 for adding test mode
	if (idx_count > 0) PrivInfo.ophuek_flag += 1;
#else
	if (idx_count > 0) PrivInfo.ophuek_flag = 1;
#endif
	delete sql_stmt;

	PrivInfo.enc_audit_flag = 255;
	PrivInfo.dec_audit_flag = 255;

	return 0;
}

dgt_sint32 PccKredStmtGetVKeyPriv::matchTargetName(dgt_schar* target_name, dgt_sint64 cmp_name_id, dgt_uint8 case_sensitive) throw(DgcExcept)
{
	dgt_sint32 match_flag = 0;

	dgt_schar* rtv = 0;
	if (!NameStr) NameStr = new dgt_schar[513];
	dgt_sint32 name_len = 0;

	if (cmp_name_id) {
		if ((name_len=PetraNamePool->getNameLen(cmp_name_id)) > 0) {
			rtv = PetraNamePool->getName(cmp_name_id, 0, NameStr);
			if (rtv == 0) {
				ATHROWnR(DgcError(SPOS,"getName failed[name_id:%lld]",cmp_name_id),-1);
			} else {
				dgt_sint32 ret = DgcExprLang::getStrStr(target_name,NameStr,case_sensitive);
				if (ret) {
					NameStr[name_len] = 0;
					match_flag = 1;
				} else {
					// not match
					match_flag = 0;
				}
			}
		} else {
			// invalid name_id
			match_flag = 0;
		}
	} else {
		// all target
		match_flag = 1;
	}

	return match_flag;
}


dgt_uint8* PccKredStmtGetVKeyPriv::fetch() throw(DgcLdbExcept,DgcPdbExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"can't fetch without execution")),0);
	}
	if (NumRtnRows++ == 0) return (dgt_uint8*)&PrivInfo;
	THROWnR(DgcLdbExcept(DGC_EC_PD_NOT_FOUND,new DgcError(SPOS,"not found")),0);
	return 0;
}
