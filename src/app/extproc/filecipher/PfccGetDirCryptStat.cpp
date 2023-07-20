/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PfccGetDirCryptStat
 *   Implementor        :       sonsuhun
 *   Create Date        :       2017. 07. 02
 *   Description        :       get EncTgtSys table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/

#include "PfccGetDirCryptStat.h"

#include "DgcPetraWorker.h"

PfccGetDirCryptStat::PfccGetDirCryptStat(const dgt_schar* name,
                                         PfccAgentListener* agent_listener)
    : PfccAgentProcedure(name, agent_listener) {}

PfccGetDirCryptStat::~PfccGetDirCryptStat() {}

DgcExtProcedure* PfccGetDirCryptStat::clone() {
    return new PfccGetDirCryptStat(procName(), AgentListener);
}

dgt_sint32 PfccGetDirCryptStat::initialize() throw(DgcExcept) { return 0; }

dgt_sint32 PfccGetDirCryptStat::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    pfcc_get_dir_crypt_stat_in* stat_in =
        (pfcc_get_dir_crypt_stat_in*)BindRows->data();
    if (AgentSession)
        AgentListener->agentSessPool().returnSession(AgentSession);
    AgentSession = AgentListener->agentSessPool().getSession(stat_in->agent_id);
    if (AgentSession == 0) {
        THROWnR(DgcDgExcept(
                    DGC_EC_DG_INVALID_STAT,
                    new DgcError(SPOS, "agent[%lld] has no available session\n",
                                 stat_in->agent_id)),
                -1);
    }
    dgt_schar sql_text[256] = {
        0,
    };
    sprintf(sql_text, "getDirCryptStat");
    DgcCliStmt* cli_stmt = AgentSession->getStmt();
    ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);
    if (cli_stmt->open(sql_text, strlen(sql_text))) {
        AgentSession->setBrokenFlag();
        if (AgentSession)
            AgentListener->agentSessPool().returnSession(AgentSession);
        DgcExcept* e = EXCEPTnC;
        delete cli_stmt;
        cli_stmt = 0;
        RTHROWnR(e, DgcError(SPOS, "open failed"), -1);
    }

    DgcMemRows bind_vars(3);
    bind_vars.addAttr(DGC_SB8, 0, "job_id");
    bind_vars.addAttr(DGC_SB8, 0, "enc_zone_id");
    bind_vars.addAttr(DGC_SB8, 0, "dir_id");
    bind_vars.reset();
    bind_vars.add();
    bind_vars.next();
    pcct_get_dir_crypt_stat* dir_crypt_stat =
        (pcct_get_dir_crypt_stat*)bind_vars.data();
    dir_crypt_stat->job_id = stat_in->job_id;
    dir_crypt_stat->enc_zone_id = stat_in->enc_zone_id;
    dir_crypt_stat->dir_id = stat_in->enc_job_tgt_id;

    if (cli_stmt->execute(10, &bind_vars) < 0) {
        AgentSession->setBrokenFlag();
        if (AgentSession)
            AgentListener->agentSessPool().returnSession(AgentSession);
        DgcExcept* e = EXCEPTnC;
        delete cli_stmt;
        cli_stmt = 0;
        // added by shson 2019.03.13
        // when session broken, occur error "Interrupted system call"
        // but occur same error message when normal session close
        // therefore when occur error "Interrupted system call" so change
        // message to "agent[%lld] sess_id[%lld] finalized"
        DgcError* err = e->getErr();
        const dgt_schar* err_msg = "";
        while (err->next()) err = err->next();
        err_msg = (dgt_schar*)err->message();
        if (strncmp(err_msg, "Interrupted system call",
                    strlen("Interrupted system call")) == 0) {
            DgcWorker::PLOG.tprintf(0, "agent[%lld] sess_id[%lld] finalized\n",
                                    AgentSession->agentID(),
                                    AgentSession->sessID());
            delete e;
            return 0;
        } else
            RTHROWnR(e, DgcError(SPOS, "execute failed"), -1);
    }
    dgt_sint32 frows = cli_stmt->fetch(1);
    if (frows < 0) {
        AgentSession->setBrokenFlag();
        if (AgentSession)
            AgentListener->agentSessPool().returnSession(AgentSession);
        DgcExcept* e = EXCEPTnC;
        delete cli_stmt;
        cli_stmt = 0;
        RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
    } else {
        ReturnRows->reset();
        DgcMemRows* rtn_rows = cli_stmt->returnRows();
        if (rtn_rows) {
            rtn_rows->rewind();
            if (rtn_rows->next()) {
                pcct_crypt_stat* stat = (pcct_crypt_stat*)rtn_rows->data();
                ReturnRows->add();
                ReturnRows->next();
                if (ReturnRows->data()) {
                    memcpy(ReturnRows->data(), stat, sizeof(pcct_crypt_stat));
                }
            }
        }
    }
    ReturnRows->rewind();
    if (cli_stmt) delete cli_stmt;
    cli_stmt = 0;
    return 0;
}
