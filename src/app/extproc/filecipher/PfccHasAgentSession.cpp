/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccHasAgentSession
 *   Implementor        :       donghun kim
 *   Create Date        :       2022. 12. 21
 *   Description        :       check pcp_crypt_agent status
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/

#include "PfccHasAgentSession.h"

PfccHasAgentSession::PfccHasAgentSession(const dgt_schar *name,
                                         PfccAgentListener *agent_listener)
    : PfccAgentProcedure(name, agent_listener) {}

PfccHasAgentSession::~PfccHasAgentSession() {}

DgcExtProcedure *PfccHasAgentSession::clone() {
    return new PfccHasAgentSession(procName(), AgentListener);
}

dgt_sint32 PfccHasAgentSession::initialize() throw(DgcExcept) { return 0; }

dgt_sint32 PfccHasAgentSession::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    pfcc_has_agent_agent_session_in *stat_in =
        (pfcc_has_agent_agent_session_in *)BindRows->data();
    if (AgentSession)
        AgentListener->agentSessPool().returnSession(AgentSession);
    AgentSession = AgentListener->agentSessPool().getSession(stat_in->agent_id);

    ReturnRows->reset();
    ReturnRows->add();
    ReturnRows->next();

    pfcc_has_agent_agent_session_out *result_out = 0;
    result_out = (pfcc_has_agent_agent_session_out *)ReturnRows->data();

    if (AgentSession)
        result_out->has_agent_session = 1;
    else
        result_out->has_agent_session = 0;

    ReturnRows->rewind();

    return 0;
}

dgt_sint32 PfccHasAgentSession::fetch() throw(DgcExcept) { return 0; }
