/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccGetTargetListStmt
 *   Implementor        :       shson
 *   Create Date        :       2018. 03.27
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccAgentStmt.h"

PccGetTargetListStmt::PccGetTargetListStmt(PccAgentCryptJobPool& job_pool)
    : PccAgentStmt(job_pool) {
    SelectListDef = new DgcClass("select_list", 8);
    SelectListDef->addAttr(DGC_SB8, 0, "job_id");
    SelectListDef->addAttr(DGC_SB8, 0, "zone_id");
    SelectListDef->addAttr(DGC_SB8, 0, "dir_id");
    SelectListDef->addAttr(DGC_SCHR, 2049, "src_file_name");
    SelectListDef->addAttr(DGC_SCHR, 2049, "dst_file_name");
    SelectListDef->addAttr(DGC_UB4, 0, "input_time");
    SelectListDef->addAttr(DGC_SB4, 0, "error_code");
    SelectListDef->addAttr(DGC_SCHR, 1025, "error_msg");

    TargetList = new DgcMemRows(8);
    TargetList->addAttr(DGC_SB8, 0, "job_id");
    TargetList->addAttr(DGC_SB8, 0, "zone_id");
    TargetList->addAttr(DGC_SB8, 0, "dir_id");
    TargetList->addAttr(DGC_SCHR, 2049, "src_file_name");
    TargetList->addAttr(DGC_SCHR, 2049, "dst_file_name");
    TargetList->addAttr(DGC_UB4, 0, "input_time");
    TargetList->addAttr(DGC_SB4, 0, "error_code");
    TargetList->addAttr(DGC_SCHR, 1025, "error_msg");
}

PccGetTargetListStmt::~PccGetTargetListStmt() {
    if (TargetList) delete TargetList;
}

dgt_sint32 PccGetTargetListStmt::execute(
    DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcExcept) {
    if (!mrows || !mrows->next()) {
        THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,
                               new DgcError(SPOS, "no bind row")),
                -1);
    }
    defineUserVars(mrows);
    pcct_target_list_in* param_in = (pcct_target_list_in*)mrows->data();

    PccAgentCryptJob* job = 0;
    if ((job = JobPool.getJob(param_in->job_id)) == 0) {
        ATHROWnR(DgcError(SPOS, "getJob[%lld] failed.", param_in->job_id), -1);
        THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,
                               new DgcError(SPOS, "not found job [%lld].",
                                            param_in->job_id)),
                -1);
    }

    PccCryptTargetFileQueue* FileQueue = 0;
    switch (param_in->target_type) {
        case 1:
            FileQueue = &(job->repository().fileQueue());
            break;
        case 2:
            FileQueue = &(job->repository().failFileQueue());
            break;
        case 3:
            FileQueue = &(job->repository().nullityFileQueue());
            break;
        default:
            THROWnR(
                DgcDbNetExcept(DGC_EC_DN_INVALID_ST,
                               new DgcError(SPOS, "invalied target_type [%d].",
                                            param_in->target_type)),
                -1);
    }
    TargetList->reset();
    FileQueue->queueCopy(TargetList);
    job->unlockShare();
    TargetList->rewind();
    IsExecuted = 1;
    return 0;
}

dgt_uint8* PccGetTargetListStmt::fetch() throw(DgcExcept) {
    if (IsExecuted == 0) {
        THROWnR(
            DgcDbNetExcept(DGC_EC_DN_INVALID_ST,
                           new DgcError(SPOS, "can't fetch without execution")),
            0);
    }
    if (TargetList->next())
        return (dgt_uint8*)TargetList->data();
    else
        return 0;
    return 0;
}
