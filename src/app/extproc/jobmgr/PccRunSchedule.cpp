/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccRunSchedule
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 3. 6
 *   Description        :       encrypt table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccRunSchedule.h"


PccRunSchedule::PccRunSchedule(const dgt_schar* name)
	: DgcExtProcedure(name)
{
}


PccRunSchedule::~PccRunSchedule()
{
}


DgcExtProcedure* PccRunSchedule::clone()
{
	return new PccRunSchedule(procName());
}


#include "PetraCipherSchedule.h"


dgt_sint32 PccRunSchedule::execute() throw(DgcExcept)
{
	if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"invalid parameter")),-1);
	}
	dgt_sint64*	schedule_id=(dgt_sint64*)BindRows->data();

#if 0 // commented out by chchung 2012.4.20, to allow time-based schedule to be run by user
	//
	// check executing mode, it should be "call-base"
	//
	dgt_schar	sql_text[128];
	sprintf(sql_text,"select * from pct_schedule where schedule_id=%lld", *schedule_id);
	DgcSqlStmt*	sql_stmt=Database->getStmt(Session,sql_text,strlen(sql_text));
	if (sql_stmt == 0 || sql_stmt->execute() < 0) {
		DgcExcept*      e=EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"execute failed."),-1);
	}
	pct_type_schedule*	schedule;
	if (!(schedule=(pct_type_schedule*)sql_stmt->fetch())) {
		DgcExcept*      e=EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"fetch failed."),-1);
	}
	delete sql_stmt;
#endif
	//
	// start a schedule
	//
	dgt_worker*	wa;
	if ((wa=Database->getWorker(Session)) == 0) {
		ATHROWnR(DgcError(SPOS,"getWorker failed"),-1);
	}
        dg_strncpy(wa->Owner,DGC_SYS_OWNER,strlen(DGC_SYS_OWNER));
        wa->PID=DgcDbProcess::pa().pid;
        wa->LWID=wa->WID;


	PetraCipherSchedule*	pcs=new PetraCipherSchedule(*schedule_id,wa,0);
	if (pcs->initialize()) {
		DgcExcept*	e=EXCEPTnC;
		delete pcs;
		RTHROWnR(e,DgcError(SPOS,"initialize[Schedule:%lld] failed",*schedule_id),-1);
	}
	if (pcs->start() != 0) {
		DgcExcept*	e=EXCEPTnC;
		if (e->classid() == DGC_EXT_WORKER) delete pcs;
		RTHROWnR(e,DgcError(SPOS,"start[Schedule:%lld] failed",*schedule_id),-1);
	}
	ReturnRows->reset();
	ReturnRows->add();
	ReturnRows->next();
	*(ReturnRows->data())=0;
	dg_sprintf((dgt_schar*)ReturnRows->data(),"schedule[%lld] started",*schedule_id);
	ReturnRows->rewind();
	return 0;
}
