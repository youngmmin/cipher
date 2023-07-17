/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccMetaProcedure
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 21
 *   Description        :       get script
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccMetaProcedure.h"
#include "PccOraScriptBuilder.h"
#include "PccTdsScriptBuilder.h"
#include "PccTds2000ScriptBuilder.h"



PccMetaProcedure::PccMetaProcedure(const dgt_schar* name)
	: DgcExtProcedure(name)
{
}


PccMetaProcedure::~PccMetaProcedure()
{
}


#include "PccScriptBuilderFactory.h"


PccScriptBuilder* PccMetaProcedure::getScriptBuilder(dgt_sint64 id,dgt_uint8 id_type) throw(DgcExcept)
{
	return PccScriptBuilderFactory::getScriptBuilder(Database,Session,id,id_type);
}

dgt_sint32 PccMetaProcedure::getScript(
	dgt_sint64 enc_tab_id,
	dgt_uint16 version_no,
	dgt_sint16 step_no,
	dgt_sint16 stmt_no,
	DgcMemRows* rtn_rows) throw(DgcExcept)
{
	PccScriptBuilder*	builder=getScriptBuilder(enc_tab_id,PCC_ID_TYPE_TABLE);
	if (!builder) {
		ATHROWnR(DgcError(SPOS,"getScriptBuilder failed."), -1);
	}
	if (builder->getScript(enc_tab_id,version_no,step_no,stmt_no,rtn_rows,1) < 0) {
		DgcExcept*	e=EXCEPTnC;
		delete builder;
		RTHROWnR(e,DgcError(SPOS,"getScript failed."), -1);
	}
	delete builder;
	return 0;
}
