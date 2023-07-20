/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccRunMigVerify
 *   Implementor        :       mwpark
 *   Create Date        :       2015. 8. 14
 *   Description        :       run a migration verify
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccRunMigVerify.h"

PccRunMigVerify::PccRunMigVerify(const dgt_schar* name)
    : DgcExtProcedure(name) {}

PccRunMigVerify::~PccRunMigVerify() {}

DgcExtProcedure* PccRunMigVerify::clone() {
    return new PccRunMigVerify(procName());
}

#include "PetraCipherMigVerifySchedule.h"

dgt_sint32 PccRunMigVerify::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    dgt_sint64* job_id = (dgt_sint64*)BindRows->data();
    //
    // check executing mode, it should be "call-base"
    //
    dgt_schar sql_text[512];
    sprintf(sql_text,
            "select b.* from pct_verify_job a, pct_schedule b where "
            "a.verify_job_id=%lld and a.schedule_id=b.schedule_id",
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

    memset(sql_text, 0, 512);
    sprintf(sql_text,
            "update PCT_VERIFY_JOB "
            "set(ROW_VERIFY_CNT_RESULT,DATA_VERIFY_RESULT)=(0,0) where "
            "VERIFY_JOB_ID=%lld",
            *job_id);
    sql_stmt = DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text,
                                          strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) delete EXCEPTnC;
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

    PetraCipherMigVerifySchedule* pcs =
        new PetraCipherMigVerifySchedule(schedule_id, wa, *job_id);
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
