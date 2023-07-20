/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PfccAlertDeadProcess
 *   Implementor        :       jhpark
 *   Create Date        :       2017. 9. 28
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PfccAlertDeadProcess.h"

#include "DgcSqlHandle.h"
#include "PcAlert.h"
#include "PfccTableTypes.h"

PfccAlertDeadProcess::PfccAlertDeadProcess(const dgt_schar* name)
    : DgcExtProcedure(name) {}

PfccAlertDeadProcess::~PfccAlertDeadProcess() {}

DgcExtProcedure* PfccAlertDeadProcess::clone() {
    return new PfccAlertDeadProcess(procName());
}

dgt_sint32 PfccAlertDeadProcess::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    pfct_alert_dead_proc_in* param = (pfct_alert_dead_proc_in*)BindRows->data();

    DgcSqlHandle sql_handle(DgcDbProcess::sess());
    dgt_schar stext[256];
    memset(stext, 0, 256);
    // 1. get job_id
    sprintf(stext,
            "select * from pfct_enc_tgt_sys "
            "where enc_tgt_sys_id = %lld ",
            param->enc_tgt_sys_id);

    if (sql_handle.execute(stext) < 0) {
        ATHROWnR(DgcError(SPOS, "execute failed"), -1);
    }
    dgt_sint32 ret = 0;
    dgt_void* rtn_row = 0;
    if ((ret = sql_handle.fetch(rtn_row)) < 0) {
        ATHROWnR(DgcError(SPOS, "fetch failed"), -1);
    }

    pfct_type_enc_tgt_sys tgt_sys;
    if (rtn_row) memcpy(&tgt_sys, rtn_row, sizeof(pfct_type_enc_tgt_sys));

    //
    // alert an event for dead process
    //
    dgt_schar* msg = new dgt_schar[512];
    sprintf(msg, "system[%s] found a dead process[%lld:%s].\n", tgt_sys.name,
            param->dead_pid, param->pname);
    if (PcAlert::p()->sendAlert(DgcDbProcess::sess(), PT_ALERT_CATEGORY1_PETRA,
                                PT_ALERT_CATEGORY2_PETRA_PROCESS,
                                PT_ALERT_EVENT_PETRA_PROCESS_DEAD, msg) != 0) {
        delete msg;
        ATHROWnR(DgcError(SPOS, "sendAlert failed"), -1);
    }
    delete msg;

    dgt_sint32 rtn = 0;

    ReturnRows->reset();
    ReturnRows->add();
    ReturnRows->next();
    *(ReturnRows->data()) = 0;
    dg_memcpy(ReturnRows->data(), &rtn, sizeof(dgt_sint32));
    ReturnRows->rewind();
    return 0;
}
