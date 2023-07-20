/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccGetDirCryptStatStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2017. 7. 1
 *   Description        :       get crypt statistics statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccAgentStmt.h"

PccGetDirCryptStatStmt::PccGetDirCryptStatStmt(PccAgentCryptJobPool& job_pool)
    : PccAgentStmt(job_pool) {
    SelectListDef = new DgcClass("select_list", 24);
    SelectListDef->addAttr(DGC_SB8, 0, "job_id");
    SelectListDef->addAttr(DGC_SB8, 0, "dir_id");
    SelectListDef->addAttr(DGC_SB8, 0, "agent_id");
    SelectListDef->addAttr(DGC_SB8, 0, "zone_id");
    SelectListDef->addAttr(DGC_SB8, 0, "filters");
    SelectListDef->addAttr(DGC_SB8, 0, "check_dirs");
    SelectListDef->addAttr(DGC_SB8, 0, "check_errors");
    SelectListDef->addAttr(DGC_SB8, 0, "target_dirs");
    SelectListDef->addAttr(DGC_SB8, 0, "check_files");
    SelectListDef->addAttr(DGC_SB8, 0, "target_files");
    SelectListDef->addAttr(DGC_SB8, 0, "input_files");
    SelectListDef->addAttr(DGC_SB8, 0, "output_files");
    SelectListDef->addAttr(DGC_SB8, 0, "crypt_errors");
    SelectListDef->addAttr(DGC_SB8, 0, "used_cores");
    SelectListDef->addAttr(DGC_SB8, 0, "used_micros");
    SelectListDef->addAttr(DGC_SB8, 0, "input_bytes");
    SelectListDef->addAttr(DGC_SB8, 0, "output_bytes");
    SelectListDef->addAttr(DGC_SB8, 0, "system_id");
    SelectListDef->addAttr(DGC_UB4, 0, "start_time");
    SelectListDef->addAttr(DGC_UB4, 0, "end_time");
    SelectListDef->addAttr(DGC_SB4, 0, "job_status");
    SelectListDef->addAttr(DGC_SB4, 0, "dir_status");
    SelectListDef->addAttr(DGC_SB8, 0, "migration_target");
    SelectListDef->addAttr(DGC_SB8, 0, "reserved");
    FetchFlag = 0;
}

PccGetDirCryptStatStmt::~PccGetDirCryptStatStmt() {}

dgt_sint32 PccGetDirCryptStatStmt::execute(
    DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcExcept) {
    if (!mrows || !mrows->next()) {
        THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,
                               new DgcError(SPOS, "no bind row")),
                -1);
    }
    defineUserVars(mrows);
    pcct_get_dir_crypt_stat* param = (pcct_get_dir_crypt_stat*)mrows->data();
    PccCryptDir* curr_dir = 0;
    PccAgentCryptJob* curr_job = 0;

    // search dir_id on running job
    if ((curr_job = JobPool.getJob(param->job_id)) &&
        (curr_dir = curr_job->repository().dirPool().getCryptDirWithDid(
             param->dir_id))) {
        // found dir
        memcpy(&CryptStat, curr_dir->cryptStat(), sizeof(pcct_crypt_stat));
        CryptStat.job_id = param->job_id;
        CryptStat.agent_id = JobPool.agentID();
        if (curr_job->collector() &&
            curr_job->collector()->jobStatus() != PCC_STATUS_TYPE_RUN)
            CryptStat.job_status = curr_job->collector()->jobStatus();
        CryptStat.dir_status = curr_dir->status();
        IsExecuted = 1;
        curr_job->unlockShare();
        // return 0;

        curr_job->unlockShare();
    } else {  // not found crypt dir
        DgcWorker::PLOG.tprintf(
            0, "not found crypt dir  job_id [%lld] dir_id [%lld]\n",
            param->job_id, param->dir_id);
        DgcExcept* e = EXCEPTnC;
        if (e) {
            DgcWorker::PLOG.tprintf(0, *e, "lock[%lld] failed.\n",
                                    param->job_id);
            delete e;
        }
        CryptStat.job_id = 0;
        CryptStat.dir_id = 0;
    }

    IsExecuted = 1;
    FetchFlag = 0;
    return 0;
}

dgt_uint8* PccGetDirCryptStatStmt::fetch() throw(DgcExcept) {
    if (IsExecuted == 0) {
        THROWnR(
            DgcDbNetExcept(DGC_EC_DN_INVALID_ST,
                           new DgcError(SPOS, "can't fetch without execution")),
            0);
    }
    if (!FetchFlag) {
        FetchFlag++;
        return CryptStat.job_id ? (dgt_uint8*)&CryptStat : 0;
    }
    THROWnR(DgcDbNetExcept(NOT_FOUND, new DgcError(SPOS, "not found")), 0);
    return 0;
}
