/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccCreateKey
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 1
 *   Description        :       create key set- master, encryption key set, ecryption key set signature
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 1
#define DEBUG
#endif

#include "PciKeyMgrIf.h"
#include "PccCreateKey.h"
#include "PccTableTypes.h"

#include "DgcDbProcess.h"


PccCreateKey::PccCreateKey(const dgt_schar* name)
	: DgcExtProcedure(name)
{
}


PccCreateKey::~PccCreateKey()
{
}


DgcExtProcedure* PccCreateKey::clone()
{
	return new PccCreateKey(procName());
}


dgt_sint32 PccCreateKey::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	dgt_schar*	pw=(dgt_schar*)BindRows->data();
	if (*pw == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"null password not allowed")),-1);
	}
	DgcTableSegment* tab=(DgcTableSegment*)Database->pdb()->segMgr()->getTable("PCT_KEY");
	if (tab == 0) {
		ATHROWnR(DgcError(SPOS,"getTable[PCT_KEY] failed"),-1);
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"Table[PCT_KEY] not found")),-1);
	}
	tab->unlockShare();
	if (tab->numRows(0) > 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"A key exists already, drop it first.")),-1);
	}
	DgcRowList	rows(tab);
	rows.reset();
	if (tab->pinInsert(Session,rows,1) != 0) {
		ATHROWnR(DgcError(SPOS,"pinInsert failed"),-1);
	}
        rows.rewind();
        rows.next();
	dgt_uint32	smk_len=100;
	dgt_uint32	seks_len=3000;
	dgt_uint32	sks_len=100;
        pct_type_key*	key_row=(pct_type_key*)rows.data();
	dgt_sint32	rtn=0;
        key_row->key_id=1;

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
	if ((rtn=PCI_createKey(pw, (void*)this, key_row->smk, &smk_len, key_row->seks, &seks_len, key_row->sks, &sks_len, hsm_mode, hsm_password)) < 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"%d:%s",rtn,PCI_getKmgrErrMsg())),-1);
        }
//	key_row->create_date=dgtime(&(key_row->create_date));
	rows.rewind();
	if (tab->insertCommit(Session,rows) != 0) {
		DgcExcept*      e=EXCEPTnC;
		rows.rewind();
		if (tab->pinRollback(rows)) delete EXCEPTnC;
		RTHROWnR(e,DgcError(SPOS,"insertCommit[PCT_KEY] failed"),-1);
	}
	ReturnRows->reset();
	ReturnRows->add();
	ReturnRows->next();
	*(ReturnRows->data())=0;


        dgt_schar       sql_text[128];
        sprintf(sql_text,"select nextLastUpdate('PCT_KEY',1,1) last_update from dual");
        DgcSqlStmt*     sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
        }
        dgt_sint64      last_up=0;
	dgt_void*	rtn_tmp=0;
        if (!(rtn_tmp=sql_stmt->fetch())) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"fetch failed."),-1);
        }
	if(rtn_tmp) last_up=*((dgt_sint64*)rtn_tmp);
        delete sql_stmt;
	delete EXCEPTnC;
	key_row->last_update=last_up;

	dg_sprintf((dgt_schar*)ReturnRows->data(),"key created");
	ReturnRows->rewind();
	return 0;
}
