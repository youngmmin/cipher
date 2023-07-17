/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccDropExtIV
 *   Implementor        :       Jaehun
 *   Create Date        :       2015. 8. 2
 *   Description        :       drop an external iv
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PciKeyMgrIf.h"
#include "PccDropExtIV.h"
#include "PccTableTypes.h"

PccDropExtIV::PccDropExtIV(const dgt_schar* name)
	: DgcExtProcedure(name)
{
}

PccDropExtIV::~PccDropExtIV()
{
}

DgcExtProcedure* PccDropExtIV::clone()
{
	return new PccDropExtIV(procName());
}


dgt_sint32 PccDropExtIV::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	dgt_sint64 iv_id = *((dgt_sint64*)BindRows->data());
	DgcTableSegment* tab=(DgcTableSegment*)Database->pdb()->segMgr()->getTable("PCT_EXT_IV");
	if (tab == 0) {
		ATHROWnR(DgcError(SPOS,"getTable[PCT_EXT_IV] failed"),-1);
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"Table[PCT_EXT_IV] not found")),-1);
	}
	tab->unlockShare();
	DgcRowRef rows(tab);
	pct_type_ext_iv* iv_row = 0;
	while (rows.next() && (iv_row=(pct_type_ext_iv*)rows.data())) {
		if (iv_row->iv_id == iv_id) {
			dgt_schar sql_text[256];
			memset(sql_text,0,256);
			sprintf(sql_text,"select iv_type from pct_encrypt_key where iv_type = %u", iv_row->iv_no);
			DgcSqlStmt*     sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
			if (sql_stmt == 0 || sql_stmt->execute() < 0) {
				DgcExcept* e = EXCEPTnC;
				delete sql_stmt; sql_stmt=0;
				RTHROWnR(e,DgcError(SPOS,"execute failed"),-1);
       	                }
			dgt_uint16* kno_ptr;
       	        	if ((kno_ptr=(dgt_uint16*)sql_stmt->fetch())) {
				delete sql_stmt; sql_stmt=0;
				THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"the iv[%lld] is being used",iv_id)),-1);
                	}
			delete EXCEPTnC;
			delete sql_stmt; sql_stmt=0;
			memset(sql_text,0,256);
			sprintf(sql_text,"DELETE PCT_EXT_IV WHERE iv_id = %lld and nextLastUpdate('PCT_EXT_IV', %lld, 3) > 0", iv_id, iv_id);
			sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
			if (sql_stmt == 0 || sql_stmt->execute() < 0) {
				DgcExcept* e = EXCEPTnC;
				delete sql_stmt; sql_stmt=0;
				RTHROWnR(e,DgcError(SPOS,"delete failed"),-1);
			}
			delete sql_stmt;
			DgcWorker::PLOG.tprintf(0,"the external iv[%lld] dropped.\n",iv_id);
			break;
		}
		iv_row = 0;
	}
	if (iv_row == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"the external iv[%lld] not found",iv_id)),-1);
	}
	ReturnRows->reset();
	ReturnRows->add();
	ReturnRows->next();
	*(ReturnRows->data()) = 0;
	dg_sprintf((dgt_schar*)ReturnRows->data(),"the external iv[%lld] dropped",iv_id);
	ReturnRows->rewind();
	return 0;
}
