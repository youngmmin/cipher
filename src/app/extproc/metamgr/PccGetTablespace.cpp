/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccGetTablespace
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 21
 *   Description        :       get script
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccGetTablespace.h"
#include "PccTableTypes.h"


PccGetTablespace::PccGetTablespace(const dgt_schar* name)
	: PccMetaProcedure(name)
{
}


PccGetTablespace::~PccGetTablespace()
{
}


DgcExtProcedure* PccGetTablespace::clone()
{
	return new PccGetTablespace(procName());
}


dgt_sint32 PccGetTablespace::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	dgt_sint64*	db_agent_id;
	if (!(db_agent_id=(dgt_sint64*)BindRows->data())) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"no input row")),-1);
	}
	if (ReturnRows == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
        PccScriptBuilder*       script_builder=getScriptBuilder(*db_agent_id,PCC_ID_TYPE_AGENT);
	if (!script_builder) {
		ATHROWnR(DgcError(SPOS,"getScriptBuilder failed."),-1);
	}
	if (script_builder->getTablespace(ReturnRows)) {
		DgcExcept*	e=EXCEPTnC;
		delete script_builder;
		RTHROWnR(e,DgcError(SPOS,"getTabInfo failed."),-1);
	}
	delete script_builder;
	ReturnRows->rewind();
	return 0;
}
