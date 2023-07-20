/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccValidationFileStmt
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
#include "PccFileCryptor.h"

PccValidationFileStmt::PccValidationFileStmt(PccAgentCryptJobPool& job_pool)
    : PccAgentStmt(job_pool) {
    SelectListDef = new DgcClass("select_list", 2);
    SelectListDef->addAttr(DGC_SB4, 0, "rtn_code");
    SelectListDef->addAttr(DGC_SCHR, 1025, "error_message");
    CryptFileOut = new pcct_crypt_file_out;
}

PccValidationFileStmt::~PccValidationFileStmt() {
    if (CryptFileOut) delete CryptFileOut;
}

dgt_sint32 PccValidationFileStmt::execute(
    DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcExcept) {
    if (!mrows || !mrows->next()) {
        THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,
                               new DgcError(SPOS, "no bind row")),
                -1);
    }
    defineUserVars(mrows);

    memset(CryptFileOut, 0, sizeof(pcct_crypt_file_out));

    dgt_schar* validation_file_path = new dgt_schar[2049];
    dgt_schar* out_file_path = new dgt_schar[2049];
    memset(validation_file_path, 0, 2049);
    memset(out_file_path, 0, 2049);
    pcct_validation_file_in* param_in = (pcct_validation_file_in*)mrows->data();
    dgt_sint32 len = dg_strlen(param_in->validation_file_path);
    strncpy(validation_file_path, param_in->validation_file_path, len);
    sprintf(out_file_path, "%s_validation", validation_file_path);

    if (JobPool.traceLevel() > 10)
        DgcWorker::PLOG.tprintf(0, "validation_file_path : %s\n",
                                validation_file_path);

    // validation file
    // 1. header check and get encZoneId
    dgt_sint8 header_flag = 0;
    PccHeaderManager hm;
    if ((header_flag = hm.checkHeader(validation_file_path)) < 0) {  // error
        DgcExcept* e = 0;
        if (EXCEPT) e = EXCEPTnC;
        DgcWorker::PLOG.tprintf(0, *e, "checkHeader [%s] failed : \n",
                                validation_file_path);
        CryptFileOut->rtn_code = -1;
        strcpy(CryptFileOut->error_message, "check header failed:");
    } else if (header_flag == 0) {  // plain file
        CryptFileOut->rtn_code = 0;
        strcpy(CryptFileOut->error_message, "not encrypted file");
    } else {
#if 0
		dgt_sint32 sid = 0;
		sid = PcaApiSessionPool::getApiSession("","","","","","",0);
		PcaApiSession*  session=PcaApiSessionPool::getApiSession(sid);
		if (!session) return -1;
#endif
        dgt_sint32 session_id = -1;
        pc_type_open_sess_in sess_in;
        memset(&sess_in, 0, sizeof(sess_in));
        session_id = PcaApiSessionPool::getApiSession(
            sess_in.client_ip, sess_in.user_id, sess_in.client_program,
            sess_in.client_mac, sess_in.db_user, sess_in.os_user,
            sess_in.protocol);

        if (session_id < 0) {
            THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,
                                  new DgcError(SPOS, "openSession failed")),
                    -1);
        }

        PcaApiSession* session = PcaApiSessionPool::getApiSession(session_id);
        if (!session)
            THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,
                                  new DgcError(SPOS, "openSession failed")),
                    -1);

        dgt_sint32 rtn = 0;
        dgt_schar* out_param = 0;
        dgt_uint32 out_param_len = 0;
        rtn = session->getZoneParam(hm.encZoneId(), &out_param);
        if (rtn)
            THROWnR(DgcBgmrExcept(
                        DGC_EC_BG_INCOMPLETE,
                        new DgcError(SPOS, "get zone param failed :", rtn)),
                    -1);

        if (JobPool.traceLevel() > 10)
            DgcWorker::PLOG.tprintf(0, "zone param :%s \n", out_param);
        out_param_len = dg_strlen(out_param);
        dgt_schar* parameters = new dgt_schar[out_param_len + 1024];
        memset(parameters, 0, out_param_len + 1024);

        sprintf(parameters,
                "(mode=(crypt=validation)(overwrite_flag=on)(user_logging=on))("
                "logging_info=(ptu_id=%lld)(client_ip=%s))",
                param_in->ptu_id, param_in->client_ip);
        strcat(parameters, out_param);
        if (JobPool.traceLevel() > 10)
            DgcWorker::PLOG.tprintf(0, "crypt parameters :%s \n", parameters);
        PccFileCryptor* cryptor =
            new PccFileCryptor(0, 0, JobPool.traceLevel());
        if ((rtn = cryptor->crypt(session_id, parameters, validation_file_path,
                                  out_file_path)) < 0) {
            DgcWorker::PLOG.tprintf(0, "crypt failed: %s - %d\n",
                                    cryptor->errString(), cryptor->errCode());
            CryptFileOut->rtn_code = -1;
            sprintf(CryptFileOut->error_message, "decrypt failed [%d]: [%s]",
                    cryptor->errCode(), cryptor->errString());
        }
        delete cryptor;
        struct stat fstat;
        if (stat(out_file_path, &fstat) == 0) {
            if (hm.inFileSize() == fstat.st_size) {
                CryptFileOut->rtn_code = 1;
                strcpy(CryptFileOut->error_message, "normal encrypted file");
            } else {
                CryptFileOut->rtn_code = -1;
                strcpy(CryptFileOut->error_message,
                       "incompleteness encrypted file");
            }
            if (unlink(out_file_path) < 0) {  // remove the file
                if (JobPool.traceLevel() > 10)
                    DgcWorker::PLOG.tprintf(0, "unlink[%s] failed : %s\n",
                                            out_file_path, strerror(errno));
                CryptFileOut->rtn_code = -1;
                dgt_sint32 len = dg_strlen(strerror(errno));
                strncpy(CryptFileOut->error_message, strerror(errno),
                        len > 1024 ? 1024 : len);
            }
        }

        delete parameters;
    }

    IsExecuted = 1;
    return 0;
}

dgt_uint8* PccValidationFileStmt::fetch() throw(DgcExcept) {
    if (IsExecuted == 0) {
        THROWnR(
            DgcDbNetExcept(DGC_EC_DN_INVALID_ST,
                           new DgcError(SPOS, "can't fetch without execution")),
            0);
    }
    return (dgt_uint8*)CryptFileOut;
}
