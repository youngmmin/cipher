/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PfccPcfsGetList
 *   Implementor        :       chchung
 *   Create Date        :       2018. 07. 17
 *   Description        :       get PCFS list
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PfccPcfsGetList.h"

#include "PccPcfsMsg.h"

PfccPcfsGetList::PfccPcfsGetList(const dgt_schar* name,
                                 PfccAgentListener* agent_listener)
    : PfccAgentProcedure(name, agent_listener) {
    CliStmt = 0;
}

PfccPcfsGetList::~PfccPcfsGetList() {
    if (CliStmt) delete CliStmt;
}

DgcExtProcedure* PfccPcfsGetList::clone() {
    return new PfccPcfsGetList(procName(), AgentListener);
}

dgt_sint32 PfccPcfsGetList::initialize() throw(DgcExcept) { return 0; }

dgt_sint32 PfccPcfsGetList::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    dgt_sint64 agent_id = *((dgt_sint64*)BindRows->data());
    if (AgentSession)
        AgentListener->agentSessPool().returnSession(AgentSession);
    AgentSession = AgentListener->agentSessPool().getSession(agent_id);
    if (AgentSession == 0) {
        THROWnR(DgcDgExcept(
                    DGC_EC_DG_INVALID_STAT,
                    new DgcError(SPOS, "agent[%lld] has no available session\n",
                                 agent_id)),
                -1);
    }
    dgt_schar sql_text[256] = {
        0,
    };
    sprintf(sql_text, "pcfsGetList");
    if (CliStmt) {
        delete CliStmt;
        CliStmt = 0;
    }
    CliStmt = AgentSession->getStmt();
    ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);
    if (CliStmt->open(sql_text, strlen(sql_text))) {
        AgentSession->setBrokenFlag();
        DgcExcept* e = EXCEPTnC;
        RTHROWnR(e, DgcError(SPOS, "open failed"), -1);
    }
    if (CliStmt->execute(500) < 0) {
        AgentSession->setBrokenFlag();
        DgcExcept* e = EXCEPTnC;
        RTHROWnR(e, DgcError(SPOS, "execute failed"), -1);
    }
    dgt_sint32 frows = CliStmt->fetch(500);
    if (frows < 0) {
        AgentSession->setBrokenFlag();
        DgcExcept* e = EXCEPTnC;
        RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
    } else {
        ReturnRows->reset();
        DgcMemRows* rtn_rows = CliStmt->returnRows();
        if (rtn_rows) {
            rtn_rows->rewind();
            while (rtn_rows->next()) {
                pcfst_fs_list* pcfs_list = (pcfst_fs_list*)rtn_rows->data();
                ReturnRows->add();
                ReturnRows->next();
                if (ReturnRows->data()) {
                    memcpy(ReturnRows->data(), pcfs_list,
                           sizeof(pcfst_fs_list));
                }
            }
        }
    }
    ReturnRows->rewind();
    return 0;
}

dgt_sint32 PfccPcfsGetList::fetch() throw(DgcExcept) {
    if (CliStmt->check() < 0)
        ATHROWnR(DgcError(SPOS, "client stmt check failed"), -1);
    dgt_sint32 frows = CliStmt->fetch(500);
    if (frows < 0) {
        DgcExcept* e = EXCEPTnC;
        RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
    } else {
        ReturnRows->reset();
        DgcMemRows* rtn_rows = CliStmt->returnRows();
        if (rtn_rows) {
            if (rtn_rows->numRows() == 0) {
                CliStmt->close();
            } else {
                while (rtn_rows->next()) {
                    pcfst_fs_list* pcfs_list = (pcfst_fs_list*)rtn_rows->data();
                    ReturnRows->add();
                    ReturnRows->next();
                    if (ReturnRows->data()) {
                        memcpy(ReturnRows->data(), pcfs_list,
                               sizeof(pcfst_fs_list));
                    }
                }
                ReturnRows->rewind();
            }
        }
    }
    return 0;
}
