/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PcbJobRunner
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 3. 5
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcbJobRunner.h"

#include "DgcPetraWorker.h"
#include "DgcPipeStream.h"

dgt_sint32 PcbJobRunner::startJob(dgt_schar* arg1,
                                  dgt_schar* arg2) throw(DgcExcept) {
    pid_t pid = 0;
    if ((pid = fork()) == 0) {
        //
        // child, pcb_job process
        //
        dgt_schar bin_path[512];
        dg_sprintf(bin_path, "%s/bin/pcb_job", dg_getenv("SOHA_HOME"));
        dgt_schar* args[4] = {(dgt_schar*)"pcb_job", arg1, arg2, 0};
        execv(bin_path, args);
        //
        // execv error
        //
        printf("execv[pcb_job %s %s] failed due to [%s].\n", arg1, arg2,
               strerror(errno));
        exit(0);
    } else if (pid < 0) {
        THROWnR(DgcDgExcept(
                    DGC_EC_PD_NOT_FOUND,
                    new DgcError(SPOS, "fork failed [%s]", strerror(errno))),
                -1);
    }
    return 0;
}

dgt_sint32 PcbJobRunner::startJob(dgt_sint64 job_id) throw(DgcExcept) {
    dgt_schar arg1[32];
    sprintf(arg1, "job_id=%lld", job_id);
    return startJob(arg1);
}

dgt_sint32 PcbJobRunner::startJob(dgt_sint64 enc_tab_id,
                                  dgt_sint16 target_step) throw(DgcExcept) {
    dgt_schar arg1[32];
    sprintf(arg1, "table_id=%lld", enc_tab_id);
    dgt_schar arg2[32];
    sprintf(arg1, "target_step=%d", target_step);
    return startJob(arg1, arg2);
}

dgt_sint32 PcbJobRunner::startMigVerify(dgt_schar* arg1) throw(DgcExcept) {
    pid_t pid = 0;
    if ((pid = fork()) == 0) {
        //
        // child, pcb_job process
        //
        dgt_schar bin_path[512];
        dg_sprintf(bin_path, "%s/bin/pcb_mig_verify", dg_getenv("SOHA_HOME"));
        dgt_schar* args[3] = {(dgt_schar*)"pcb_mig_verify", arg1, 0};
        execv(bin_path, args);
        //
        // execv error
        //
        printf("execv[pcb_mig_verify %s] failed due to [%s].\n", arg1,
               strerror(errno));
        exit(0);
    } else if (pid < 0) {
        THROWnR(DgcDgExcept(
                    DGC_EC_PD_NOT_FOUND,
                    new DgcError(SPOS, "fork failed [%s]", strerror(errno))),
                -1);
    }
    return 0;
}

dgt_sint32 PcbJobRunner::startMigVerify(dgt_sint64 job_id) throw(DgcExcept) {
    dgt_schar arg1[32];
    sprintf(arg1, "job_id=%lld", job_id);
    return startMigVerify(arg1);
}
