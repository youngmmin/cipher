/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccAgentStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2017. 6. 30
 *   Description        :       agent server statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccAgentStmt.h"

PccAgentStmt::PccAgentStmt(PccAgentCryptJobPool& job_pool)
	: JobPool(job_pool), UserVarRows(0), SelectListDef(0), IsExecuted(0)
{
}
	
PccAgentStmt::~PccAgentStmt()
{
	delete SelectListDef;
	delete UserVarRows;
}

dgt_sint32 PccAgentStmt::defineUserVars(DgcMemRows* mrows) throw(DgcExcept)
{
	if (UserVarRows) delete UserVarRows;
	UserVarRows=mrows;
	return 0;
}

dgt_sint32 PccAgentStmt::execute(DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcExcept)
{
	return 0;
}

DgcClass* PccAgentStmt::fetchListDef() throw(DgcExcept)
{
	if (SelectListDef == 0) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"fetch row format not defined yet")),0);
	}
	return SelectListDef;
}

dgt_uint8* PccAgentStmt::fetch() throw(DgcExcept)
{
	return 0;
}
