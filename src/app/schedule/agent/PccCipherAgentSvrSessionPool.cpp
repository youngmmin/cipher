/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccFileCipherService
 *   Implementor        :       Jaehun
 *   Create Date        :       2017. 6. 29
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccCipherAgentSvrSessionPool.h"

PccCipherAgentSvrSessionPool::PccCipherAgentSvrSessionPool()
    : PrimaryPort(0), SecondaryPort(0) {
    memset(PrimaryIP, 0, 257);
    memset(SecondaryIP, 0, 257);
    for (dgt_sint32 i = 0; i < MAX_NUM_AGENT_SVR_SESS; i++)
        AgentSvrSession[i] = 0;
    NumAgentSvrSess = MAX_NUM_AGENT_SVR_SESS;
}

PccCipherAgentSvrSessionPool::~PccCipherAgentSvrSessionPool() {
    for (dgt_sint32 i = 0; i < MAX_NUM_AGENT_SVR_SESS; i++) {
        if (AgentSvrSession[i]) {
            dgt_sint32 wait_cnt = 0;
            while (AgentSvrSession[i]->isAlive() && wait_cnt < 5000) {
                napAtick();
                wait_cnt++;
            }
            if (!AgentSvrSession[i]->isAlive()) delete AgentSvrSession[i];
        }
    }
}

dgt_sint32 PccCipherAgentSvrSessionPool::cleanBrokenSessions() throw(
    DgcExcept) {
    dgt_sint32 clean_session_count = 0;
    for (dgt_sint32 i = 0; i < NumAgentSvrSess; i++) {
        if (AgentSvrSession[i]) {
            if (AgentSvrSession[i]->brokenConnFlag()) {
                AgentSvrSession[i]->askStop();
                while (AgentSvrSession[i]->isAlive()) napAtick();
                delete AgentSvrSession[i];
                AgentSvrSession[i] = 0;
                clean_session_count++;
            }  // if (AgentSvrSession[i]->brokenConnFlag()) end
        }      // if (AgentSvrSession[i]) end
    }          // for (dgt_sint32 i=0; i<NumAgentSvrSess; i++) end

    return clean_session_count;
}

dgt_sint32 PccCipherAgentSvrSessionPool::startNewSessions(
    PccAgentCryptJobPool& job_pool,
    dgt_sint32 no_sess_sleep_cnt) throw(DgcExcept) {
    dgt_sint32 new_session_count = 0;
    for (dgt_sint32 i = 0; i < NumAgentSvrSess; i++) {
        if (AgentSvrSession[i] == 0) {
            AgentSvrSession[i] = new PccCipherAgentSvrSession(
                job_pool, i + 1, no_sess_sleep_cnt, PrimaryIP, PrimaryPort,
                SecondaryIP, SecondaryPort);
            if (AgentSvrSession[i]->connect() < 0) {
                delete AgentSvrSession[i];
                AgentSvrSession[i] = 0;
                ATHROWnR(DgcError(SPOS,
                                  "agent[%lld] agent_svr_session[%d] connect "
                                  "failed while starting\n",
                                  job_pool.agentID(), i + 1),
                         -1);
            }
            if (AgentSvrSession[i]->start(1)) {
                delete AgentSvrSession[i];
                AgentSvrSession[i] = 0;
                ATHROWnR(
                    DgcError(SPOS, "start agent_svr_session[%d] failed", i + 1),
                    -1);
            }
            DgcWorker::PLOG.tprintf(0, "agent_svr_session[%d] restarting\n",
                                    i + 1);
            new_session_count++;
        }
    }
    return new_session_count;
}

dgt_sint32 PccCipherAgentSvrSessionPool::startSessions(
    PccAgentCryptJobPool& job_pool,
    dgt_sint32 no_sess_sleep_cnt) throw(DgcExcept) {
    for (dgt_sint32 i = 0; i < NumAgentSvrSess; i++) {
        if (AgentSvrSession[i]) {
            AgentSvrSession[i]->askStop();
            while (AgentSvrSession[i]->isAlive()) napAtick();
            delete AgentSvrSession[i];
            AgentSvrSession[i] = 0;
        }
        AgentSvrSession[i] = new PccCipherAgentSvrSession(
            job_pool, i + 1, no_sess_sleep_cnt, PrimaryIP, PrimaryPort,
            SecondaryIP, SecondaryPort);
        if (AgentSvrSession[i]->connect() < 0) {
            DgcExcept* e = EXCEPTnC;
            if (e) {
                DgcWorker::PLOG.tprintf(0, *e,
                                        "agent[%lld] agent_svr_session[%d] "
                                        "connect failed while starting\n",
                                        job_pool.agentID(), i + 1);
                delete e;
            }
        }
        if (AgentSvrSession[i]->start(1)) {
            ATHROWnR(
                DgcError(SPOS, "start agent_svr_session[%d] failed", i + 1),
                -1);
        }
    }
    return 0;
}

dgt_sint32 PccCipherAgentSvrSessionPool::stopSessions() throw(DgcExcept) {
    for (dgt_sint32 i = 0; i < NumAgentSvrSess; i++) {
        if (AgentSvrSession[i]) {
            AgentSvrSession[i]->askStop();
            while (AgentSvrSession[i]->isAlive()) napAtick();
            delete AgentSvrSession[i];
            AgentSvrSession[i] = 0;
        }
    }
    return 0;
}

dgt_sint32 PccCipherAgentSvrSessionPool::initialize(
    DgcBgrammer* sess_info) throw(DgcExcept) {
    dgt_schar* val;
    NumAgentSvrSess = 1;

    if ((val = sess_info->getValue("agent.num_sessions"))) {
        NumAgentSvrSess = (dgt_sint32)strtol(val, 0, 10);
    }

    if (NumAgentSvrSess > MAX_NUM_AGENT_SVR_SESS) {
        NumAgentSvrSess = MAX_NUM_AGENT_SVR_SESS;
    }

    if ((val = sess_info->getValue("agent.soha.primary.ip"))) {
        strncpy(PrimaryIP, val, 256);
    }

    if ((val = sess_info->getValue("agent.soha.primary.pfcc_port"))) {
        PrimaryPort = (dgt_uint16)strtol(val, 0, 10);
    }

    if ((val = sess_info->getValue("agent.soha.secondary.ip"))) {
        strncpy(SecondaryIP, val, 256);
    }

    if ((val = sess_info->getValue("agent.soha.secondary.pfcc_port"))) {
        SecondaryPort = (dgt_uint16)strtol(val, 0, 10);
    }

    if (*PrimaryIP == 0 || PrimaryPort == 0) {
        THROWnR(
            DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,
                          new DgcError(SPOS, "primary ip or port not defined")),
            -1);
    }

    return 0;
}
