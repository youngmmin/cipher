/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PfccGetDetectInfo
 *   Implementor        :       sonsuhun
 *   Create Date        :       2017. 05. 24
 *   Description        :       get EncTgtSys table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PfccGetDetectInfo.h"

#include "PcaCharSetCnvt.h"

PfccGetDetectInfo::PfccGetDetectInfo(const dgt_schar* name,
                                     PfccAgentListener* agent_listener)
    : PfccAgentProcedure(name, agent_listener) {
    pr_debug("new procedure!\n");
}

PfccGetDetectInfo::~PfccGetDetectInfo() { pr_debug("delete procedure!\n"); }

DgcExtProcedure* PfccGetDetectInfo::clone() {
    return new PfccGetDetectInfo(procName(), AgentListener);
}

dgt_sint32 PfccGetDetectInfo::initialize() throw(DgcExcept) { return 0; }

dgt_sint32 PfccGetDetectInfo::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    pfcc_get_detect_info_in* param_in =
        (pfcc_get_detect_info_in*)BindRows->data();
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
    DgcMemRows bind_vars(2);
    bind_vars.addAttr(DGC_SCHR, 2048, "FILE_NAME");
    bind_vars.addAttr(DGC_SCHR, 1024, "PARAMETER");
    bind_vars.reset();
    bind_vars.add();
    bind_vars.next();
    memcpy(bind_vars.getColPtr(1), param_in->file_name,
           strlen(param_in->file_name));
    memcpy(bind_vars.getColPtr(2), param_in->parameter,
           strlen(param_in->parameter));
    pcct_detect_info_in* info_in = (pcct_detect_info_in*)bind_vars.data();

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
    sprintf(sql_text, "getDetectInfo");

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
    dgt_schar conv_parameter[1024] = {0};
    if (convert_flag) {
        pr_debug(
            "before file_name[%s] file_name_len[%d] param[%s] param_len[%d]\n",
            info_in->file_name,
            (dgt_sint32)strlen(info_in->file_name, info_in->parameter,
                               (dgt_sint32)strlen(info_in->parameter)));
        memset(conv_file_name, 0, sizeof(conv_file_name));
        memset(conv_parameter, 0, sizeof(conv_parameter));
        if ((rtn = charset->convert(info_in->file_name,
                                    strlen(info_in->file_name), conv_file_name,
                                    sizeof(conv_file_name))) > 0) {
            memset(info_in->file_name, 0, sizeof(info_in->file_name));
            memcpy(info_in->file_name, conv_file_name,
                   sizeof(info_in->file_name));
        }
        if ((rtn = charset->convert(info_in->parameter,
                                    strlen(info_in->parameter), conv_parameter,
                                    sizeof(conv_parameter))) > 0) {
            memset(info_in->parameter, 0, sizeof(info_in->parameter));
            memcpy(info_in->parameter, conv_parameter,
                   sizeof(info_in->parameter));
        }
        // for fetch - when fetch, file_name must be converting to utf-8
        charset->setCharSet("UTF-8", agent_charset);
    }
    pr_debug(
        "file_name[%s] file_name_len[%d] param[%s] param_len[%d] "
        "converting_flag [%d]\n",
        info_in->file_name, (dgt_sint32)strlen(info_in->file_name),
        info_in->parameter, (dgt_sint32)strlen(info_in->parameter),
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
    // 7. fetching
    //
    dgt_sint32 frows = 0;
    while ((frows = cli_stmt->fetch())) {
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
        }
    }

    ReturnRows->reset();
    DgcMemRows* rtn_rows = cli_stmt->returnRows();
    rtn_rows->rewind();
    while (rtn_rows && rtn_rows->next()) {
        pcct_detect_info_out* info_out =
            (pcct_detect_info_out*)rtn_rows->data();
        if (convert_flag) {
            dgt_schar conv_expr[1024] = {0};
            dgt_schar conv_data[1024] = {0};
            if ((rtn = charset->convert(info_out->expr, strlen(info_out->expr),
                                        conv_expr, sizeof(conv_expr))) > 0) {
                memset(info_out->expr, 0, strlen(info_out->expr));
                memcpy(info_out->expr, conv_expr, strlen(conv_expr));
            }
            if ((rtn = charset->convert(info_out->data, strlen(info_out->data),
                                        conv_data, sizeof(conv_data))) > 0) {
                memset(info_out->data, 0, strlen(info_out->data));
                memcpy(info_out->data, conv_data, strlen(conv_data));
            }
        }
        ReturnRows->add();
        ReturnRows->next();
        memcpy(ReturnRows->data(), info_out, sizeof(pcct_detect_info_out));
        pr_debug("so[%lld] eo[%lld] data_seq[%d] expr[%s] data[%s]\n",
                 info_out->start_offset, info_out->end_offset,
                 info_out->data_seq, info_out->expr, info_out->data);
    }

    ReturnRows->rewind();
    if (charset) delete charset;
    if (cli_stmt) delete cli_stmt;
    cli_stmt = 0;
    return 0;
}
