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
#ifndef PFCC_HAS_AGENT_SESSION_H
#define PFCC_HAS_AGENT_SESSION_H

#include "PfccAgentProcedure.h"

typedef struct {
    dgt_sint64 agent_id;
} pfcc_has_agent_agent_session_in;

typedef struct {
    dgt_uint8 has_agent_session;
} pfcc_has_agent_agent_session_out;

class PfccHasAgentSession : public PfccAgentProcedure {
   private:
   protected:
   public:
    PfccHasAgentSession(const dgt_schar *name,
                        PfccAgentListener *agent_listener);
    virtual ~PfccHasAgentSession();
    virtual DgcExtProcedure *clone();
    virtual dgt_sint32 initialize() throw(DgcExcept);
    virtual dgt_sint32 execute() throw(DgcExcept);
    virtual dgt_sint32 fetch() throw(DgcExcept);
};

#endif
