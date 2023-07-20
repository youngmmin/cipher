/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccAgentProdecure
 *   Implementor        :       jhpark
 *   Create Date        :       2017. 07. 02
 *   Description        :       base prodedure to commnicate with agent
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/

#include "PfccAgentProcedure.h"

PfccAgentProcedure::PfccAgentProcedure(const dgt_schar* name,
                                       PfccAgentListener* agent_listener)
    : DgcExtProcedure(name), AgentListener(agent_listener), AgentSession(0) {}

PfccAgentProcedure::~PfccAgentProcedure() {
    if (AgentListener && AgentSession)
        AgentListener->agentSessPool().returnSession(AgentSession);
}

dgt_sint32 PfccAgentProcedure::initialize() throw(DgcExcept) { return 0; }
