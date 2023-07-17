/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccRunScript
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 2. 25
 *   Description        :       run cipher script
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccRunScript.h"


PccRunScript::PccRunScript(const dgt_schar* name)
	: PccMetaProcedure(name)
{
}


PccRunScript::~PccRunScript()
{
}


DgcExtProcedure* PccRunScript::clone()
{
	return new PccRunScript(procName());
}


dgt_sint32 PccRunScript::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	if (!(InRow=(dgt_run_script_in*)BindRows->data())) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"no input row")),-1);
	}
	if (ReturnRows == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	//
	// get script builder for DBMS connection
	//
	PccScriptBuilder*	script_builder=getScriptBuilder(InRow->enc_tab_id, PCC_ID_TYPE_AGENT);
	if (!script_builder) {
		ATHROWnR(DgcError(SPOS,"getScriptBuilder failed."),-1);
	}
	//
	// get script to run
	//
	dgt_sint32	rtn;
	if ((rtn=script_builder->getScript(InRow->enc_tab_id, InRow->version_no, InRow->step_no, InRow->stmt_no)) > 0) {
		//
		// run script
		//
		if (script_builder->runScript(script_builder->scriptText()) < 0) {
			DgcExcept*	e=EXCEPTnC;
			delete script_builder;
			RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
		}
	} else if (rtn < 0) {
		DgcExcept*	e=EXCEPTnC;
		delete script_builder;
		RTHROWnR(e,DgcError(SPOS,"getScript failed."),-1);
	}
	delete script_builder;
	ReturnRows->reset();
	ReturnRows->add();
	ReturnRows->next();
	memset(ReturnRows->data(),0,ReturnRows->rowSize());
	sprintf((dgt_schar*)ReturnRows->data(),"script[%d] run.",rtn);
        ReturnRows->rewind();
	return 0;
}
