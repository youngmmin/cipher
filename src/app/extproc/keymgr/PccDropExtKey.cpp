/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccDropExtKey
 *   Implementor        :       Jaehun
 *   Create Date        :       2015. 8. 2
 *   Description        :       drop an external key
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PciKeyMgrIf.h"
#include "PccDropExtKey.h"
#include "PccTableTypes.h"

PccDropExtKey::PccDropExtKey(const dgt_schar* name)
	: DgcExtProcedure(name)
{
}

PccDropExtKey::~PccDropExtKey()
{
}

DgcExtProcedure* PccDropExtKey::clone()
{
	return new PccDropExtKey(procName());
}


dgt_sint32 PccDropExtKey::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	dgt_sint64 key_id = *((dgt_sint64*)BindRows->data());
	DgcTableSegment* tab=(DgcTableSegment*)Database->pdb()->segMgr()->getTable("PCT_EXT_KEY");
	if (tab == 0) {
		ATHROWnR(DgcError(SPOS,"getTable[PCT_EXT_KEY] failed"),-1);
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"Table[PCT_EXT_KEY] not found")),-1);
	}
	tab->unlockShare();
	DgcRowRef rows(tab);
	pct_type_ext_key* key_row = 0;
	while (rows.next() && (key_row=(pct_type_ext_key*)rows.data())) {
		if (key_row->key_id == key_id) {
			dgt_schar sql_text[256];
			memset(sql_text,0,256);
			sprintf(sql_text,"select key_no from pct_encrypt_key where key_no = %u", key_row->key_no);
			DgcSqlStmt*     sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
			if (sql_stmt == 0 || sql_stmt->execute() < 0) {
				DgcExcept* e = EXCEPTnC;
				delete sql_stmt; sql_stmt=0;
				RTHROWnR(e,DgcError(SPOS,"execute failed"),-1);
       	                }
			dgt_uint16* kno_ptr;
       	        	if ((kno_ptr=(dgt_uint16*)sql_stmt->fetch())) {
				delete sql_stmt; sql_stmt=0;
				THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"the key[%lld] is being used",key_id)),-1);
                	}
			delete EXCEPTnC;
			delete sql_stmt; sql_stmt=0;
			memset(sql_text,0,256);
			sprintf(sql_text,"DELETE PCT_EXT_KEY WHERE KEY_ID = %lld and nextLastUpdate('PCT_EXT_KEY', %lld, 3) > 0", key_id, key_id);
			sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
			if (sql_stmt == 0 || sql_stmt->execute() < 0) {
				DgcExcept* e = EXCEPTnC;
				delete sql_stmt; sql_stmt=0;
				RTHROWnR(e,DgcError(SPOS,"delete failed"),-1);
			}
			delete sql_stmt;
			DgcWorker::PLOG.tprintf(0,"the external key[%lld] dropped.\n",key_id);
			break;
		}
		key_row = 0;
	}
	if (key_row == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"the external key[%lld] not found",key_id)),-1);
	}
	ReturnRows->reset();
	ReturnRows->add();
	ReturnRows->next();
	*(ReturnRows->data()) = 0;
	dg_sprintf((dgt_schar*)ReturnRows->data(),"the external key[%lld] dropped",key_id);
	ReturnRows->rewind();
	return 0;
}
