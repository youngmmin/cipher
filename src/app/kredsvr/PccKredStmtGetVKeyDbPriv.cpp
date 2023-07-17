/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtGetVKeyDbPriv
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :       KRED get key statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtGetVKeyDbPriv.h"
#include "DgcDbProcess.h"
#include "DgcExprLang.h"

PccKredStmtGetVKeyDbPriv::PccKredStmtGetVKeyDbPriv(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term)
	: PccKredStmtGetVKeyPriv(pdb, session, stmt_term)
{

}


PccKredStmtGetVKeyDbPriv::~PccKredStmtGetVKeyDbPriv()
{
}


dgt_sint32 PccKredStmtGetVKeyDbPriv::execute(DgcMemRows* mrows,dgt_sint8 delete_flag) throw(DgcLdbExcept,DgcPdbExcept)
{
	if (!mrows || !mrows->next()) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"no bind row")),-1);
	}
	defineUserVars(mrows);
	pc_type_get_vkey_db_priv_in*	brow = (pc_type_get_vkey_db_priv_in*)mrows->data();
	memset(&PrivInfo, 0, sizeof(PrivInfo));

	if (getEncColumn(brow->virtual_key_id,brow->user_sid,brow->crypt_type) < 0) ATHROWnR(DgcError(SPOS,"getEncColumn failed"),-1);

	// PrivInfo.dec_priv = PccDecPrivilege::DEC_ALLOW
	// PrivInfo.dec_priv = PccDecPrivilege::DEC_REJECT_SRC;
	// PrivInfo.dec_priv = PccDecPrivilege::DEC_REJECT_MASKING;
	// PrivInfo.dec_priv = PccDecPrivilege::DEC_REJECT_ERR;

	//
	// get privilege
	//
	PrivInfo.dec_priv = PccDecPrivilege::DEC_REJECT_ERR;

	dgt_schar* db_name = brow->name1;
	dgt_schar* schema_name = brow->name2;
	dgt_schar* db_sess_user_name = brow->name3;
	dgt_schar* table_name = brow->name4;
	dgt_schar* column_name = brow->name5;

	if (EncColumn.enc_col_id) {
		//
		// check target list
		//
		DgcTableSegment* cipher_vkey_target_tab = PetraTableHandler->getTable("pvat_cipher_vkey_target");
		if (!cipher_vkey_target_tab) ATHROWnR(DgcError(SPOS,"getTable[pvat_cipher_vkey_target] failed"),-1);
		DgcIndexSegment* cipher_vkey_target_idx = PetraTableHandler->getIndex("pvat_cipher_vkey_target_idx1");
		if (!cipher_vkey_target_idx) ATHROWnR(DgcError(SPOS,"getIndex[pvat_cipher_vkey_target_idx1] failed"),-1);
		pvat_type_cipher_vkey_target target_row;
		memset(&target_row,0,sizeof(pvat_type_cipher_vkey_target));
		target_row.virtual_key_id = brow->virtual_key_id;
		DgcRowList target_row_list(cipher_vkey_target_tab);
		target_row_list.reset();
		if(cipher_vkey_target_idx->find((dgt_uint8*)&target_row,target_row_list,1) < 0) {
			ATHROWnR(DgcError(SPOS,"index search failed"),-1);
		}
		if (target_row_list.numRows() > 0) {
			target_row_list.rewind();
			pvat_type_cipher_vkey_target* vkey_target = 0;
			dgt_sint32 ret = 0;
			while (target_row_list.next() && (vkey_target=(pvat_type_cipher_vkey_target*)target_row_list.data())) {
				// check db_name
				if ((ret=matchTargetName(db_name,vkey_target->name1,0)) < 0) {
					DgcExcept* e = EXCEPTnC;
					if (e) {
						DgcWorker::PLOG.tprintf(0,*e,"matchTargetName failed[db_name:%s]\n",db_name);
						delete e;
					}
					continue;
				} else if(ret == 0) {
					// not matched
					continue;
				}
				// check schema_name
				if ((ret=matchTargetName(schema_name,vkey_target->name2,0)) < 0) {
					DgcExcept* e = EXCEPTnC;
					if (e) {
						DgcWorker::PLOG.tprintf(0,*e,"matchTargetName failed[schema_name:%s]\n",schema_name);
						delete e;
					}
					continue;
				} else if(ret == 0) {
					// not matched
					continue;
				}

				// check db_sess_user_name
				if ((ret=matchTargetName(db_sess_user_name,vkey_target->name3,0)) < 0) {
					DgcExcept* e = EXCEPTnC;
					if (e) {
						DgcWorker::PLOG.tprintf(0,*e,"matchTargetName failed[db_sess_user_name:%s]\n",db_sess_user_name);
						delete e;
					}
					continue;
				} else if(ret == 0) {
					// not matched
					continue;
				}

				// check table_name
				if ((ret=matchTargetName(table_name,vkey_target->name4,0)) < 0) {
					DgcExcept* e = EXCEPTnC;
					if (e) {
						DgcWorker::PLOG.tprintf(0,*e,"matchTargetName failed[table_name:%s]\n",table_name);
						delete e;
					}
					continue;
				} else if(ret == 0) {
					// not matched
					continue;
				}

				// check column_name
				if ((ret=matchTargetName(column_name,vkey_target->name5,0)) < 0) {
					DgcExcept* e = EXCEPTnC;
					if (e) {
						DgcWorker::PLOG.tprintf(0,*e,"matchTargetName failed[column_name:%s]\n",column_name);
						delete e;
					}
					continue;
				} else if(ret == 0) {
					// not matched
					continue;
				}

				PrivInfo.dec_priv = PccDecPrivilege::DEC_ALLOW;
				break;
			}
		}
	}

	IsExecuted=1;
	NumRtnRows=0;

	return 0;
}


