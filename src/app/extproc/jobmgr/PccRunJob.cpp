/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccRunJob
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 3. 6
 *   Description        :       encrypt table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccRunJob.h"

PccRunJob::PccRunJob(const dgt_schar* name) : DgcExtProcedure(name) {}

PccRunJob::~PccRunJob() {}

DgcExtProcedure* PccRunJob::clone() { return new PccRunJob(procName()); }

#include "PetraCipherSchedule.h"

dgt_sint32 PccRunJob::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    dgt_sint64* job_id = (dgt_sint64*)BindRows->data();
    //
    // check executing mode, it should be "call-base"
    //
    dgt_schar sql_text[128];
    sprintf(sql_text,
            "select b.* from pct_job a, pct_schedule b where a.job_id=%lld and "
            "a.schedule_id=b.schedule_id",
            *job_id);
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    pct_type_schedule* schedule;
    if (!(schedule = (pct_type_schedule*)sql_stmt->fetch())) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "fetch failed."), -1);
    }
    dgt_sint64 schedule_id = schedule->schedule_id;
    delete sql_stmt;
    //
    // start a schedule with only one job
    //
    dgt_worker* wa;
    if ((wa = DgcDbProcess::db().getWorker(DgcDbProcess::sess())) == 0)
        ATHROWnR(DgcError(SPOS, "getWorker failed"), -1);
    dg_strncpy(wa->Owner, DGC_SYS_OWNER, strlen(DGC_SYS_OWNER));
    wa->PID = DgcDbProcess::pa().pid;
    wa->LWID = wa->WID;

    PetraCipherSchedule* pcs =
        new PetraCipherSchedule(schedule_id, wa, *job_id);
    if (pcs->initialize()) {
        DgcExcept* e = EXCEPTnC;
        delete pcs;
        RTHROWnR(e,
                 DgcError(SPOS, "initialize[Schedule:%lld:%lld] failed",
                          schedule_id, *job_id),
                 -1);
    }
    if (pcs->start() != 0) {
        DgcExcept* e = EXCEPTnC;
        if (e->classid() == DGC_EXT_WORKER) delete pcs;
        RTHROWnR(e,
                 DgcError(SPOS, "start[Schedule:%lld:%lld] failed", schedule_id,
                          *job_id),
                 -1);
    }
    ReturnRows->reset();
    ReturnRows->add();
    ReturnRows->next();
    *(ReturnRows->data()) = 0;
    dg_sprintf((dgt_schar*)ReturnRows->data(), "schedule[%lld:%lld] started",
               schedule_id, *job_id);
    ReturnRows->rewind();
    return 0;
}
