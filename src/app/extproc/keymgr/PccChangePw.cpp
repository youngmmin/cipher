/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccChangePw
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 1
 *   Description        :       change password
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PciKeyMgrIf.h"
#include "PccChangePw.h"
#include "PccTableTypes.h"
#include "DgcDbProcess.h"
#include "PcSyncIudLogInserter.h"
#include "DgcDbProcess.h"


PccChangePw::PccChangePw(const dgt_schar* name)
	: DgcExtProcedure(name)
{
}


PccChangePw::~PccChangePw()
{
}


DgcExtProcedure* PccChangePw::clone()
{
	return new PccChangePw(procName());
}


dgt_sint32 PccChangePw::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	dgt_schar*	old_pw=0;
	dgt_schar*	new_pw=0;
	if ((old_pw=(dgt_schar*)BindRows->getColPtr(1)) == 0 ||
	    (new_pw=(dgt_schar*)BindRows->getColPtr(2)) == 0) {
		ATHROWnR(DgcError(SPOS,"getColPtr failed"),-1);
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"null password not allowed")),-1);
	}
	DgcTableSegment* tab=(DgcTableSegment*)Database->pdb()->segMgr()->getTable("PCT_KEY");
	if (tab == 0) {
		ATHROWnR(DgcError(SPOS,"getTable[PCT_KEY] failed"),-1);
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"Table[PCT_KEY] not found")),-1);
	}
	tab->unlockShare();
	DgcRowRef	key_rows(tab);
	if (key_rows.next()) {
		pct_type_key*	key_row=(pct_type_key*)key_rows.data();
#if 1
                dgt_schar       sql_text[256];
                memset(sql_text,0,256);
                sprintf(sql_text,"select * from pct_key_stat where key_id=%lld",key_row->key_id);
                DgcSqlStmt*     sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
		if (!sql_stmt) {
        	        ATHROWnR(DgcError(SPOS,"getStmt failed"),-1);
	        }
        	if (sql_stmt->execute() >= 0) {
                	dgt_uint8*      rowd;
	                if ((rowd=sql_stmt->fetch())) {
	        		delete sql_stmt;
                        	THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"the key opened, should be closed first")),-1);
                	}
	        }
        	delete EXCEPTnC;
	        delete sql_stmt;
        	sql_stmt=0;
#endif
		//
		// pin the key row for update
		//
		DgcRowList	rows(tab);
		rows.add(key_rows.bno(), key_rows.rno(), key_rows.data());
		rows.rewind();
		if (tab->pinUpdate(rows) != 0) {
			ATHROWnR(DgcError(SPOS,"pinUpdate failed"),-1);
		}
                //
                // change password
                //
		key_row=(pct_type_key*)rows.data();
                PcSyncIudLogInserter iud_log(Session, DgcDbProcess::db().pdb());
                dgt_sint64 last_update=iud_log.nextLastUpdate((dgt_schar*)"pct_key", key_row->key_id, PcSyncIudLogInserter::PTC_SYNC_SQL_TYPE_UPDATE);
                if (last_update < 0) {
                        ATHROWnR(DgcError(SPOS,"nextLastUpdate failed"),-1);
                }
                dgt_sint32      rtn=0;
        	//
	        // added by mwpark
        	// 2017.02.11
	        // for hsm
        	//
	        dgt_sys_param*       param;
        	dgt_sint32 hsm_mode=0;
	        dgt_schar  hsm_password[128];
        	memset(hsm_password,0,128);
	        if ((param=DG_PARAM("USE_HSM_FLAG")) == 0) delete EXCEPTnC;
        	else {
	                if (param->val_number == 1) {
				hsm_mode=1;
        	                if ((param=DG_PARAM("HSM_PASSWORD")) == 0) delete EXCEPTnC;
                	        else {
	                                strncpy(hsm_password,param->val_string,strlen(param->val_string));
        	                }
                	}
	        }
                if ((rtn=PCI_changePassword(old_pw, new_pw, key_row->smk, strlen(key_row->smk), key_row->seks,
                         strlen(key_row->seks), key_row->sks, strlen(key_row->sks), hsm_mode, hsm_password)) < 0) {
                        DgcExcept* e=EXCEPTnC;
                        if (iud_log.nextLastUpdateRollBack() < 0) delete EXCEPTnC;
                        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"%d:%s",rtn,PCI_getKmgrErrMsg())),-1);
                }
                key_row->last_update=last_update;
		//
		// commit the update
		//
		rows.rewind();
		if (tab->updateCommit(Session,rows) != 0) {
			DgcExcept*      e=EXCEPTnC;
			if (iud_log.nextLastUpdateRollBack() < 0) delete EXCEPTnC;
			RTHROWnR(e,DgcError(SPOS,"updateCommit[PCT_KEY] failed"),-1);
		}
		DgcWorker::PLOG.tprintf(0,"the master key password changed.\n");
	}
	ReturnRows->reset();
	ReturnRows->add();
	ReturnRows->next();
	*(ReturnRows->data())=0;
	dg_sprintf((dgt_schar*)ReturnRows->data(),"password changed");
	ReturnRows->rewind();
	return 0;
}
