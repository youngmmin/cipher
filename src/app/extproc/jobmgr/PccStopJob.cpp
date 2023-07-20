/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccStopJob
 *   Implementor        :       mwpark
 *   Create Date        :       2012. 08.14
 *   Description        :       Stopping encrypt job
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccStopJob.h"

PccStopJob::PccStopJob(const dgt_schar* name) : DgcExtProcedure(name) {}

PccStopJob::~PccStopJob() {}

DgcExtProcedure* PccStopJob::clone() { return new PccStopJob(procName()); }

#include "PetraCipherSchedule.h"

dgt_sint32 PccStopJob::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    dgt_sint64* job_id = (dgt_sint64*)BindRows->data();
    dgt_schar sql_text[256];
    sprintf(sql_text, "select * from pct_job a where job_id=%lld", *job_id);
    DgcSqlStmt* sql_stmt =
        Database->getStmt(Session, sql_text, strlen(sql_text));
    if (sql_stmt == 0 || sql_stmt->execute() < 0) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed."), -1);
    }
    pct_type_job job;
    dgt_uint8* tmp;
    if (!(tmp = sql_stmt->fetch())) {
        DgcExcept* e = EXCEPTnC;
        delete sql_stmt;
        RTHROWnR(e, DgcError(SPOS, "fetch failed."), -1);
    } else {
        memcpy(&job, tmp, sizeof(job));
    }
    delete sql_stmt;
    if (job.curr_status > 0 &&
        job.curr_status < PetraCipherSchedule::PCB_JOB_STATUS_PENDING) {
        //
        // job in processing
        //
        kill(job.process_id, 9);
        sprintf(sql_text,
                "update pct_job set(curr_status,curr_err_msg)=(%d,'stoped by "
                "user') where job_id=%lld",
                PetraCipherSchedule::PCB_JOB_STATUS_PENDING, *job_id);
        DgcSqlStmt* sql_stmt =
            Database->getStmt(Session, sql_text, strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
            DgcExcept* e = EXCEPTnC;
            delete sql_stmt;
            RTHROWnR(e, DgcError(SPOS, "updating job's status failed."), -1);
        }
        delete sql_stmt;
        sprintf(sql_text,
                "update pct_enc_table set(curr_enc_step,curr_enc_stmt)=(%d,%d) "
                "where enc_tab_id=%lld",
                job.curr_enc_step, job.curr_enc_stmt - 1, job.enc_tab_id);
        sql_stmt = Database->getStmt(Session, sql_text, strlen(sql_text));
        if (sql_stmt == 0 || sql_stmt->execute() < 0) {
            DgcExcept* e = EXCEPTnC;
            delete sql_stmt;
            RTHROWnR(
                e,
                DgcError(SPOS, "updating pct_enc_table`s curr_enc_step failed"),
                -1);
        }
    } else {
        THROWnR(
            DgcLdbExcept(
                DGC_EC_LD_STMT_ERR,
                new DgcError(SPOS, "The Job[%lld] not in processing", *job_id)),
            -1);
    }
    ReturnRows->reset();
    ReturnRows->add();
    ReturnRows->next();
    *(ReturnRows->data()) = 0;
    dg_sprintf((dgt_schar*)ReturnRows->data(), "job[%lld] stopped", *job_id);
    ReturnRows->rewind();
    return 0;
}
