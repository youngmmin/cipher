/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccRemoveFileStmt
 *   Implementor        :       jhpark
 *   Create Date        :       2018. 1. 24
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "DgcBgmrList.h"
#include "PccAgentStmt.h"

PccRemoveFileStmt::PccRemoveFileStmt(PccAgentCryptJobPool& job_pool)
    : PccAgentStmt(job_pool) {
    SelectListDef = new DgcClass("select_list", 2);
    SelectListDef->addAttr(DGC_SB4, 0, "rtn_code");
    SelectListDef->addAttr(DGC_SCHR, 1025, "error_message");
    CryptFileOut = new pcct_crypt_file_out;
}

PccRemoveFileStmt::~PccRemoveFileStmt() {
    if (CryptFileOut) delete CryptFileOut;
}

dgt_sint32 PccRemoveFileStmt::execute(DgcMemRows* mrows,
                                      dgt_sint8 delete_flag) throw(DgcExcept) {
    if (!mrows || !mrows->next()) {
        THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,
                               new DgcError(SPOS, "no bind row")),
                -1);
    }
    defineUserVars(mrows);

    memset(CryptFileOut, 0, sizeof(pcct_crypt_file_out));

    dgt_schar* rm_file_path = new dgt_schar[2049];
    memset(rm_file_path, 0, 2049);
    dgt_schar* file_path = (dgt_schar*)mrows->data();

    if (file_path) {
        dgt_sint32 len = dg_strlen(file_path);
        strncpy(rm_file_path, file_path, len > 1024 ? 1024 : len);
    }

    if (JobPool.traceLevel() > 0)
        DgcWorker::PLOG.tprintf(0, "rm_file_path : %s\n", rm_file_path);

    // remove file
    if (unlink(rm_file_path) < 0) {  // remove the file
        if (JobPool.traceLevel() > 0)
            DgcWorker::PLOG.tprintf(0, "unlink[%s] failed : %s\n", rm_file_path,
                                    strerror(errno));
        CryptFileOut->rtn_code = -1;
        dgt_sint32 len = dg_strlen(strerror(errno));
        strncpy(CryptFileOut->error_message, strerror(errno),
                len > 1024 ? 1024 : len);
    }

    IsExecuted = 1;
    return 0;
}

dgt_uint8* PccRemoveFileStmt::fetch() throw(DgcExcept) {
    if (IsExecuted == 0) {
        THROWnR(
            DgcDbNetExcept(DGC_EC_DN_INVALID_ST,
                           new DgcError(SPOS, "can't fetch without execution")),
            0);
    }
    return (dgt_uint8*)CryptFileOut;
}
