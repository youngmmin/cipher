/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccGenScriptColAdmin
 *   Implementor        :       Mwpark
 *   Create Date        :       2014. 12. 17
 *   Description        :       generate script
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccGenScriptColAdmin.h"


PccGenScriptColAdmin::PccGenScriptColAdmin(const dgt_schar* name)
	: PccMetaProcedure(name)
{
}


PccGenScriptColAdmin::~PccGenScriptColAdmin()
{
}


DgcExtProcedure* PccGenScriptColAdmin::clone()
{
	return new PccGenScriptColAdmin(procName());
}

dgt_sint32 PccGenScriptColAdmin::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	dgt_sint64*	enc_tab_id;
	if (!(enc_tab_id=(dgt_sint64*)BindRows->data())) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"no input row")),-1);
	}
	if (ReturnRows == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	PccScriptBuilder*	script_builder=getScriptBuilder(*enc_tab_id,PCC_ID_TYPE_TABLE);
	if (!script_builder) {
		ATHROWnR(DgcError(SPOS,"getScriptBuilder failed."),-1);
	}
        //
        // delete old scripts
        //
        dgt_schar       sql_text[256];
        sprintf(sql_text,"delete pct_script where enc_tab_id=%lld and step_no=3",*enc_tab_id);
        DgcSqlStmt*     sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                DgcExcept*      e=EXCEPTnC;
                delete sql_stmt;
                RTHROWnR(e,DgcError(SPOS,"delete failed."),-1);
        }
        delete sql_stmt;
	//
	// build new scripts
	//
	if (script_builder->buildScriptColAdmin(*enc_tab_id,0)) {
		DgcExcept*	e=EXCEPTnC;
		delete script_builder;
		RTHROWnR(e,DgcError(SPOS,"buildScript failed"),-1);
	}
	delete script_builder;
	ReturnRows->reset();
	ReturnRows->add();
	ReturnRows->next();
	memset(ReturnRows->data(),0,ReturnRows->rowSize());
        sprintf((dgt_schar*)ReturnRows->data(),"scripts generated.");
        ReturnRows->rewind();
	return 0;
}
