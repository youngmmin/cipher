/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PfccPcfsGetStat
 *   Implementor        :       sonsuhun
 *   Create Date        :       2017. 07. 02
 *   Description        :       get EncTgtSys table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PfccPcfsGetStat.h"

#include "PccPcfsMsg.h"

PfccPcfsGetStat::PfccPcfsGetStat(const dgt_schar* name,
                                 PfccAgentListener* agent_listener)
    : PfccAgentProcedure(name, agent_listener) {
    CliStmt = 0;
}

PfccPcfsGetStat::~PfccPcfsGetStat() {
    if (CliStmt) delete CliStmt;
}

DgcExtProcedure* PfccPcfsGetStat::clone() {
    return new PfccPcfsGetStat(procName(), AgentListener);
}

dgt_sint32 PfccPcfsGetStat::initialize() throw(DgcExcept) { return 0; }

dgt_sint32 PfccPcfsGetStat::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    pfcc_pcfs_get_stat_in* stat_in = (pfcc_pcfs_get_stat_in*)BindRows->data();
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
    sprintf(sql_text, "pcfsGetStat");
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
    DgcMemRows bind_vars(1);
    bind_vars.addAttr(DGC_UB2, 0, "pcfs_id");
    bind_vars.add();
    bind_vars.rewind();
    bind_vars.next();
    *((dgt_uint16*)bind_vars.data()) = stat_in->pcfs_id;

    if (CliStmt->execute(500, &bind_vars) < 0) {
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
                pcfst_fs_stat* stat = (pcfst_fs_stat*)rtn_rows->data();
                ReturnRows->add();
                ReturnRows->next();
                if (ReturnRows->data()) {
                    memcpy(ReturnRows->data(), stat, sizeof(pcfst_fs_stat));
                }
            }
        }
    }
    ReturnRows->rewind();
    return 0;
}

dgt_sint32 PfccPcfsGetStat::fetch() throw(DgcExcept) {
    if (CliStmt->check() < 0)
        ATHROWnR(DgcError(SPOS, "client stamt check failed"), -1);
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
                    pcfst_fs_stat* stat = (pcfst_fs_stat*)rtn_rows->data();
                    ReturnRows->add();
                    ReturnRows->next();
                    if (ReturnRows->data()) {
                        memcpy(ReturnRows->data(), stat, sizeof(pcfst_fs_stat));
                    }
                }
                ReturnRows->rewind();
            }
        }
    }
    return 0;
}
