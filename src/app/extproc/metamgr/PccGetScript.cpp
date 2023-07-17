/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccGetScript
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 21
 *   Description        :       get script
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccGetScript.h"
#include "PccTableTypes.h"


PccGetScript::PccGetScript(const dgt_schar* name)
	: PccMetaProcedure(name)
{
}


PccGetScript::~PccGetScript()
{
}


DgcExtProcedure* PccGetScript::clone()
{
	return new PccGetScript(procName());
}


dgt_sint32 PccGetScript::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	if (!(InRow=(pc_type_get_script_in*)BindRows->data())) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"no input row")),-1);
	}
	if (ReturnRows == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	ReturnRows->reset();
	if (getScript(InRow->enc_tab_id,InRow->version_no,InRow->step_no,InRow->stmt_no,ReturnRows) < 0) {
		ATHROWnR(DgcError(SPOS,"getScript failed."), -1);
	}
        ReturnRows->rewind();
	return 0;
}
