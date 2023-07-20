/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PfccVerifyDetectInfo
 *   Implementor        :       mjkim
 *   Create Date        :       2017. 07. 12
 *   Description        :       verify detection file
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PfccVerifyDetectInfo.h"

#include "PcaCharSetCnvt.h"

PfccVerifyDetectInfo::PfccVerifyDetectInfo(const dgt_schar* name,
                                           PfccAgentListener* agent_listener)
    : PfccAgentProcedure(name, agent_listener) {
    pr_debug("new procedure!\n");
}

PfccVerifyDetectInfo::~PfccVerifyDetectInfo() {
    pr_debug("delete procedure!\n");
}

DgcExtProcedure* PfccVerifyDetectInfo::clone() {
    return new PfccVerifyDetectInfo(procName(), AgentListener);
}

dgt_sint32 PfccVerifyDetectInfo::initialize() throw(DgcExcept) { return 0; }

dgt_sint32 PfccVerifyDetectInfo::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    pfcc_verify_detect_info_in* param_in =
        (pfcc_verify_detect_info_in*)BindRows->data();
    if (!param_in)
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "no input row")),
                -1);

    dgt_void* rtn_row = 0;
    dgt_schar stext[256] = {0};
    DgcSqlHandle sql_handle(DgcDbProcess::sess());

    // get charset
    dgt_sint32 convert_flag = 0;
    dgt_schar agent_charset[65] = {0};

    memset(stext, 0, sizeof(stext));
    sprintf(stext, "select char_set from pfct_agent where agent_id = %lld",
            param_in->agent_id);
    if (sql_handle.execute(stext) < 0)
        ATHROWnR(DgcError(SPOS, "execute failed"), -1);
    if (!sql_handle.fetch(rtn_row) && rtn_row) {  // fetch success
        strncpy(agent_charset, (dgt_schar*)rtn_row,
                strlen((dgt_schar*)rtn_row));
        if (strlen(agent_charset) &&
            ((strncasecmp(agent_charset, "EUC-KR", sizeof("EUC-KR")) == 0) ||
             (strncasecmp(agent_charset, "CP949", sizeof("CP949")) ==
              0)))  // need converting
            convert_flag = 1;
    }

    // prepare bind data
    memset(stext, 0, sizeof(stext));
    sprintf(stext,
            "select file_name,file_size,file_mtime from pct_file_detect_hist "
            "where job_id = %lld and dir_id = %lld and file_id = %lld",
            param_in->job_id, param_in->dir_id, param_in->file_id);
    if (sql_handle.execute(stext) < 0)
        ATHROWnR(DgcError(SPOS, "execute failed"), -1);
    if (sql_handle.fetch(rtn_row) < 0 || !rtn_row)
        ATHROWnR(DgcError(SPOS, "fetch failed"), -1);

    DgcMemRows bind_vars(3);
    bind_vars.addAttr(DGC_SCHR, 2048, "FILE_NAME");
    bind_vars.addAttr(DGC_SB8, 0, "FILE_SIZE");
    bind_vars.addAttr(DGC_UB4, 0, "FILE_MTIME");
    bind_vars.reset();
    bind_vars.add();
    bind_vars.next();
    memcpy(bind_vars.data(), rtn_row, bind_vars.rowFormat()->length());
    pcct_verify_detect_info_in* info_in =
        (pcct_verify_detect_info_in*)bind_vars.data();

    // 1. get agent session
    if (AgentSession)
        AgentListener->agentSessPool().returnSession(AgentSession);
    AgentSession =
        AgentListener->agentSessPool().getSession(param_in->agent_id);
    if (AgentSession == 0) {
        THROWnR(DgcDgExcept(
                    DGC_EC_DG_INVALID_STAT,
                    new DgcError(SPOS, "agent[%lld] has no available session\n",
                                 param_in->agent_id)),
                -1);
    }

    // 2. get agent statement
    dgt_schar sql_text[256] = {
        0,
    };
    sprintf(sql_text, "verifyDetectInfo");

    DgcCliStmt* cli_stmt = AgentSession->getStmt();
    ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);

    // 3. open
    if (cli_stmt->open(sql_text, strlen(sql_text))) {
        AgentSession->setBrokenFlag();
        if (AgentSession)
            AgentListener->agentSessPool().returnSession(AgentSession);
        DgcExcept* e = EXCEPTnC;
        // if (cli_stmt) delete cli_stmt;
        cli_stmt = 0;
        RTHROWnR(e, DgcError(SPOS, "open failed"), -1);
    }

    // 5. charset converting check
    dgt_sint32 rtn = 0;
    PcaCharSetCnvt* charset = new PcaCharSetCnvt(agent_charset, "UTF-8");
    dgt_schar conv_file_name[2048] = {0};
    if (convert_flag) {
        pr_debug("before file_name[%s] file_name_len[%d]\n", info_in->file_name,
                 (dgt_sint32)strlen(info_in->file_name));

        memset(conv_file_name, 0, sizeof(conv_file_name));
        if ((rtn = charset->convert(info_in->file_name,
                                    strlen(info_in->file_name), conv_file_name,
                                    sizeof(conv_file_name))) > 0) {
            memset(info_in->file_name, 0, sizeof(info_in->file_name));
            memcpy(info_in->file_name, conv_file_name,
                   sizeof(info_in->file_name));
        }
        // for fetch - when fetch, file_name must be converting to utf-8
        charset->setCharSet("UTF-8", agent_charset);
    }
    pr_debug("file_name[%s] file_name_len[%d] converting_flag[%d]\n",
             info_in->file_name, (dgt_sint32)strlen(info_in->file_name),
             convert_flag);

    // 6. execute
    bind_vars.rewind();
    if (cli_stmt->execute(1, &bind_vars) < 0) {
        AgentSession->setBrokenFlag();
        if (AgentSession)
            AgentListener->agentSessPool().returnSession(AgentSession);
        DgcExcept* e = EXCEPTnC;
        // if (cli_stmt) delete cli_stmt;
        if (charset) delete charset;
        charset = 0;
        cli_stmt = 0;
        RTHROWnR(e, DgcError(SPOS, "execute failed"), -1);
    }

    //
    // 7. first fetching
    //
    dgt_sint32 frows = cli_stmt->fetch();
    if (frows < 0) {
        AgentSession->setBrokenFlag();
        if (AgentSession)
            AgentListener->agentSessPool().returnSession(AgentSession);
        DgcExcept* e = EXCEPTnC;
        // if (cli_stmt) delete cli_stmt;
        if (charset) delete charset;
        charset = 0;
        cli_stmt = 0;
        RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
    } else {
        ReturnRows->reset();
        DgcMemRows* rtn_rows = cli_stmt->returnRows();
        if (rtn_rows) {
            rtn_rows->rewind();
            if (rtn_rows->next()) {
                ReturnRows->add();
                ReturnRows->next();
                memcpy(ReturnRows->data(), rtn_rows->data(),
                       sizeof(pcct_verify_detect_info_out));
                pr_debug("rtn_code [%d] error_messgae [%s] \n",
                         info_out->rtn_code, info_out->error_message);
            }
        }
    }

    ReturnRows->rewind();
    if (charset) delete charset;
    if (cli_stmt) delete cli_stmt;
    cli_stmt = 0;
    return 0;
}
