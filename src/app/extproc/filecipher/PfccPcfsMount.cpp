/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PfccPcfsMount
 *   Implementor        :       chchung
 *   Create Date        :       2018. 07. 17
 *   Description        :       mount or unmount PCFS
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PfccPcfsMount.h"

#include "PccPcfsMsg.h"

PfccPcfsMount::PfccPcfsMount(const dgt_schar* name,
                             PfccAgentListener* agent_listener)
    : PfccAgentProcedure(name, agent_listener) {
    CliStmt = 0;
}

PfccPcfsMount::~PfccPcfsMount() {
    if (CliStmt) delete CliStmt;
}

DgcExtProcedure* PfccPcfsMount::clone() {
    return new PfccPcfsMount(procName(), AgentListener);
}

dgt_sint32 PfccPcfsMount::initialize() throw(DgcExcept) { return 0; }

dgt_sint32 PfccPcfsMount::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    pfcc_pcfs_mount_in* mount_in = (pfcc_pcfs_mount_in*)BindRows->data();
    if (AgentSession)
        AgentListener->agentSessPool().returnSession(AgentSession);
    AgentSession =
        AgentListener->agentSessPool().getSession(mount_in->agent_id);
    if (AgentSession == 0) {
        THROWnR(DgcDgExcept(
                    DGC_EC_DG_INVALID_STAT,
                    new DgcError(SPOS, "agent[%lld] has no available session\n",
                                 mount_in->agent_id)),
                -1);
    }
    dgt_schar sql_text[256] = {
        0,
    };
    sprintf(sql_text, "pcfsMount");
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

    DgcMemRows bind_vars(2);
    bind_vars.addAttr(DGC_UB2, 0, "pcfs_id");
    bind_vars.addAttr(DGC_UB2, 0, "mount_type");
    bind_vars.add();
    bind_vars.rewind();
    bind_vars.next();
    pcfst_mount_rqst* mount_rqst = (pcfst_mount_rqst*)bind_vars.data();
    mount_rqst->pcfs_id = mount_in->pcfs_id;
    mount_rqst->mount_type = mount_in->mount_type;

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
                ReturnRows->add();
                ReturnRows->next();
                if (ReturnRows->data()) {
                    memcpy(ReturnRows->data(), rtn_rows->data(), 300);
                }
            }
        }
    }
    ReturnRows->rewind();
    return 0;
}

dgt_sint32 PfccPcfsMount::fetch() throw(DgcExcept) {
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
                    ReturnRows->add();
                    ReturnRows->next();
                    if (ReturnRows->data()) {
                        memcpy(ReturnRows->data(), rtn_rows->data(), 300);
                    }
                }
                ReturnRows->rewind();
            }
        }
    }
    return 0;
}
