/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccDecrypt
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 3. 6
 *   Description        :       encrypt table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccDecrypt.h"


PccDecrypt::PccDecrypt(const dgt_schar* name)
	: DgcExtProcedure(name)
{
}


PccDecrypt::~PccDecrypt()
{
}


DgcExtProcedure* PccDecrypt::clone()
{
	return new PccDecrypt(procName());
}


#include "PcbJobRunner.h"


dgt_sint32 PccDecrypt::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	dgt_sint64*	enc_tab_id=(dgt_sint64*)BindRows->data();
	if (PcbJobRunner::startJob(*enc_tab_id,0)) {
		ATHROWnR(DgcError(SPOS,"startJob[%lld,0] failed", *enc_tab_id),-1);
	}
	ReturnRows->reset();
	ReturnRows->add();
	ReturnRows->next();
	*(ReturnRows->data())=0;
	dg_sprintf((dgt_schar*)ReturnRows->data(),"decrypting[0] started");
	ReturnRows->rewind();
	return 0;
}
