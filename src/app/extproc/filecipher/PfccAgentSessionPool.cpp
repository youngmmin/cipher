/*******************************************************************
 *   File Type          :
 *   Classes            :       PfccAgentSessionPool
 *   Implementor        :       jhpark
 *   Create Date        :       2018. 2. 2
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PfccAgentSessionPool.h"

#include "DgcDgConstType.h"
#include "DgcSqlHandle.h"

PfccSohaConnection::PfccSohaConnection()
    : DgcSohaConnection(DGC_MAX_OPEN_CURSORS) {}

PfccSohaConnection::~PfccSohaConnection() {}

dgt_sint32 PfccSohaConnection::checkConnection() throw(DgcExcept) {
    DgcExcept* e = 0;
    dgt_sint8 rtn = 0;
    if ((rtn = MsgStream->recvMessage(1)) < 0) {
        ATHROWnR(DgcError(SPOS, "recvMessage failed"), -1);
    } else if (rtn > 0) {
        if (MsgStream->currMsg()->opi() != PTDGILETTER) {
            ATHROWnR(DgcError(SPOS, "invalid request message[%d:%d:%d]",
                              MsgStream->currMsg()->tti(),
                              MsgStream->currMsg()->opi(),
                              MsgStream->currMsg()->seq()),
                     -1);
        }

        PtMsgDgiLetter check_conn(1);
        if (MsgStream->sendMessage(&check_conn) != 0) {
            ATHROWnR(DgcError(SPOS, "sendMessage failed"), -1);
        }
    }
    return 0;
}

PfccAgentSession::PfccAgentSession() : AgentIpAddr(0) {
    memset(&AgentInfo, 0, sizeof(pcct_get_agent_info));
    UseFlag = 0;
    BrokenFlag = 0;
}

PfccAgentSession::~PfccAgentSession() {}

dgt_sint32 PfccAgentSession::getAgentInfo() throw(DgcExcept) {
    dgt_schar sql_text[256] = {
        0,
    };
    sprintf(sql_text, "getAgentInfo");
    DgcCliStmt* cli_stmt = Connection.getStmt();
    ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);
    if (cli_stmt->open(sql_text, strlen(sql_text))) {
        DgcExcept* e = EXCEPTnC;
        delete cli_stmt;
        RTHROWnR(e, DgcError(SPOS, "open failed"), -1);
    }
    if (cli_stmt->execute(1) < 0) {
        DgcExcept* e = EXCEPTnC;
        delete cli_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed"), -1);
    }
    dgt_sint32 frows = cli_stmt->fetch(1);
    if (frows < 0) {
        DgcExcept* e = EXCEPTnC;
        delete cli_stmt;
        RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
    } else {
        DgcMemRows* rtn_rows = cli_stmt->returnRows();
        if (rtn_rows && rtn_rows->next()) {
            memcpy(&AgentInfo, rtn_rows->data(), sizeof(pcct_get_agent_info));
        }
    }
    delete cli_stmt;
    return 0;
}

dgt_sint32 PfccAgentSession::setInitParams() throw(DgcExcept) {
    // 1. get enc_job
    DgcTableSegment* enc_job_tab = PetraTableHandler->getTable("pfct_enc_job");
    if (!enc_job_tab)
        ATHROWnR(DgcError(SPOS, "getTable[pfct_enc_job] failed"), -1);
    DgcIndexSegment* enc_job_idx2 =
        PetraTableHandler->getIndex("pfct_enc_job_idx2");
    if (!enc_job_idx2)
        ATHROWnR(DgcError(SPOS, "getIndex[pfct_enc_job_idx2] failed"), -1);

    pfct_type_enc_job job_rows;
    memset(&job_rows, 0, sizeof(pfct_type_enc_job));
    job_rows.agent_id = AgentInfo.agent_id;

    DgcRowList job_row_list(enc_job_tab);
    job_row_list.reset();
    if (enc_job_idx2->find((dgt_uint8*)&job_rows, job_row_list, 1) < 0) {
        ATHROWnR(DgcError(SPOS, "enc_job_idx2 search failed"), -1);
    }

    dgt_sint32 offset = 0;
    dgt_sint32 remain = 0;
    pcct_set_params* set_params = 0;
    PfccAgentParamBuilder param_builder(AgentInfo.agent_id, 1);
    DgcMemRows bind_vars(7);
    bind_vars.addAttr(DGC_SB8, 0, "job_id");
    bind_vars.addAttr(DGC_SB8, 0, "last_update");
    bind_vars.addAttr(DGC_SB4, 0, "max_target_files");
    bind_vars.addAttr(DGC_SB4, 0, "collecting_interval");
    bind_vars.addAttr(DGC_UB1, 0, "job_type");
    bind_vars.addAttr(DGC_UB1, 0, "status");
    bind_vars.addAttr(DGC_SCHR, 1025, "params");

    // 2. build agent parameters and execute setParams statement
    dgt_sint32 ret = 0;
    dgt_void* rtn_row = 0;
    pfct_type_enc_job* enc_job = 0;
    while (job_row_list.next() &&
           (enc_job = (pfct_type_enc_job*)job_row_list.data())) {
        if (enc_job->job_type == PCC_AGENT_TYPE_TEMPORARY_JOB) continue;
        if (enc_job->status == PCC_STATUS_TYPE_DELETED) {
            // update agent_last_update even deleted
            enc_job->agent_last_update = enc_job->last_update;
            continue;
        }

        dgt_sint32 rtn = 0;
        // build param
        if ((rtn = param_builder.buildAgentParams(
                 enc_job->enc_job_id, enc_job->schedule_date_id)) < 0) {
            if (rtn == -901130 &&
                strncmp(enc_job->name, "default", sizeof(enc_job->name)) ==
                    0) {  // when pfct_enc_job_tgt not found about job
                DgcExcept* e = EXCEPTnC;
                delete e;
                DgcWorker::PLOG.tprintf(
                    0,
                    "setInitParams default configuration job don't has "
                    "enc_job_tgt, this message is not Error\n");
                continue;
            } else {
                ATHROWnR(DgcError(SPOS, "buildAgentParams failed"), -1);
            }
        }
        bind_vars.reset();

        offset = 0;
        remain = (dgt_sint32)param_builder.agentParamSize();
        // pr_debug("job_id[%lld]
        // agent_param_size[%u]\n",enc_job->enc_job_id,param_builder.agentParamSize());
        // pr_debug("param:\n%s\n",param_builder.agentParam());
        set_params = 0;
        // build bind values
        while (remain > 0) {
            bind_vars.add();
            bind_vars.next();
            set_params = (pcct_set_params*)bind_vars.data();
            if (!set_params) continue;
            set_params->job_id = enc_job->enc_job_id;
            set_params->last_update = enc_job->last_update;
            set_params->max_target_files = enc_job->max_target_files;
            set_params->collecting_interval = enc_job->collecting_interval;
            set_params->job_type = enc_job->job_type;
            set_params->status = enc_job->status;

            if (remain >= 1024) {
                memcpy(set_params->data, param_builder.agentParam() + offset,
                       1024);
                offset += 1024;
                remain -= 1024;
            } else {
                memcpy(set_params->data, param_builder.agentParam() + offset,
                       remain);
                offset += remain;
                remain = 0;
            }
        }

        dgt_schar sql_text[256] = {
            0,
        };
        sprintf(sql_text, "setParams");
        DgcCliStmt* cli_stmt = Connection.getStmt();
        ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);
        if (cli_stmt->open(sql_text, strlen(sql_text))) {
            DgcExcept* e = EXCEPTnC;
            delete cli_stmt;
            RTHROWnR(e, DgcError(SPOS, "open failed"), -1);
        }

        // execute stmt
        bind_vars.rewind();
        if (cli_stmt->execute(10, &bind_vars) < 0) {
            DgcExcept* e = EXCEPTnC;
            delete cli_stmt;
            RTHROWnR(e, DgcError(SPOS, "execute failed"), -1);
        }
        delete cli_stmt;

        enc_job->agent_last_update = enc_job->last_update;
    }

    // update agent_last_update
    if (enc_job_tab->pinUpdate(job_row_list) < 0)
        ATHROWnR(DgcError(SPOS, "pinUpdate failed"), -1);
    job_row_list.rewind();
    if (enc_job_tab->updateCommit(DgcDbProcess::sess(), job_row_list) < 0) {
        ATHROWnR(DgcError(SPOS, "updateCommit failed"), -1);
    }

    return 0;
}

dgt_sint32 PfccAgentSession::connect(DgcCommStream* stream) throw(DgcExcept) {
    dgt_sint32 rtn = Connection.connect(stream);
    if (rtn < 0) {
        ATHROWnR(DgcError(SPOS, "connect failed"), -1);
    }

    if (getAgentInfo() < 0) {
        DgcExcept* e = EXCEPTnC;
        RTHROWnR(e, DgcError(SPOS, "getAgentInfo failed"), -1);
    }
    if (AgentInfo.last_update == 0 && AgentInfo.sess_id == 1 &&
        setInitParams()) {
        DgcExcept* e = EXCEPTnC;
        if (e) {
            DgcWorker::PLOG.tprintf(0, *e, "setInitParams failed:\n");
            delete e;
        }
    }

    dgt_schar sip[65];
    DgcSockStream* st = (DgcSockStream*)stream;
    struct sockaddr_in cli_addr;
    dgt_uint16 len = sizeof(cli_addr);
    if (st->peerAddr((dgt_schar*)&cli_addr, &len) != 0) {
        DgcExcept* e = EXCEPTnC;
        e->addErr(new DgcError(SPOS, "peerAddr failed"));
        DgcWorker::PLOG.tprintf(0, *e, "putenv failed:");
        delete e;
    } else {
        AgentIpAddr = cli_addr.sin_addr.s_addr;
    }

    DgcWorker::PLOG.tprintf(0, "agent[%lld] sess_id[%d] initialized.\n",
                            AgentInfo.agent_id, AgentInfo.sess_id);

    return 0;
}

PfccAgentSessionPool::PfccAgentSessionPool() {
    for (dgt_sint32 i = 0; i < PFCC_MAX_AGENT_SESS_NUM; i++) AgentSess[i] = 0;
    unlock();
}

PfccAgentSessionPool::~PfccAgentSessionPool() {
    for (dgt_sint32 i = 0; i < PFCC_MAX_AGENT_SESS_NUM; i++) {
        if (AgentSess[i] != 0) delete AgentSess[i];
    }
}

dgt_sint32 PfccAgentSessionPool::addSession(PfccAgentSession* session) throw(
    DgcExcept) {
    // check prev session is exist
    if (lock() == 0) {
        for (dgt_sint32 i = 0; i < PFCC_MAX_AGENT_SESS_NUM; i++) {
            if (AgentSess[i] && AgentSess[i]->agentID() == session->agentID() &&
                AgentSess[i]->agentIpAddr() == session->agentIpAddr() &&
                AgentSess[i]->sessID() == session->sessID()) {
                delete AgentSess[i];
                AgentSess[i] = session;
                session = 0;
                break;
            }
        }
        if (session) {
            // establish new session
            for (dgt_sint32 i = 0; i < PFCC_MAX_AGENT_SESS_NUM; i++) {
                if (AgentSess[i] == 0) {
                    AgentSess[i] = session;
                    session = 0;
                    break;
                }
            }
        }
        unlock();
    }

    if (session) {
        THROWnR(DgcDgExcept(DGC_EC_DG_INVALID_STAT,
                            new DgcError(
                                SPOS, "agent[%lld] session[%d] pool is full.\n",
                                session->agentID(), session->sessID())),
                -1);
    }
    return 0;
}

dgt_void PfccAgentSessionPool::removeSession(PfccAgentSession* session) {
    if (lock() == 0) {
        for (dgt_sint32 i = 0; i < PFCC_MAX_AGENT_SESS_NUM; i++) {
            if (AgentSess[i] && AgentSess[i]->agentID() == session->agentID() &&
                AgentSess[i]->sessID() == session->sessID()) {
                delete AgentSess[i];
                AgentSess[i] = 0;
                session = 0;
                break;
            }
        }
        unlock();
    }
}

PfccAgentSession* PfccAgentSessionPool::getSession(dgt_sint64 agent_id) {
    PfccAgentSession* session = 0;
    if (lock() == 0) {
        for (dgt_sint32 i = 0; i < PFCC_MAX_AGENT_SESS_NUM; i++) {
            if (AgentSess[i] && AgentSess[i]->agentID() == agent_id &&
                AgentSess[i]->isUsing() == 0 && AgentSess[i]->isBroken() == 0) {
                session = AgentSess[i];
                session->setUseFlag();
                break;
            }
        }
        unlock();
    }
    return session;
}

PfccAgentSession* PfccAgentSessionPool::getSessionIdx(dgt_sint32 idx) {
    PfccAgentSession* session = 0;
    if (lock() == 0) {
        if (AgentSess[idx] && AgentSess[idx]->isUsing() == 0) {
            session = AgentSess[idx];
            session->setUseFlag();
        }
        unlock();
    }
    return session;
}

dgt_void PfccAgentSessionPool::returnSession(PfccAgentSession* session) {
    if (!session) return;
    if (lock() == 0) {
        session->unsetUseFlag();
        unlock();
    }
}
