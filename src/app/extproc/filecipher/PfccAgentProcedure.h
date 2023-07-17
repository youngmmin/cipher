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
#ifndef PFCC_AGENT_PROCEDURE_H
#define PFCC_AGENT_PROCEDURE_H

#include "DgcDgConstType.h"
#include "DgcExtProcedure.h"
#include "PfccAgentProcSvr.h"

class PfccAgentProcedure : public DgcExtProcedure {
  private:
  protected:
	PfccAgentListener*	AgentListener;
	PfccAgentSession*	AgentSession;
  public:
	PfccAgentProcedure(const dgt_schar* name, PfccAgentListener* agent_listener);
	virtual ~PfccAgentProcedure();

	virtual dgt_sint32 initialize() throw(DgcExcept);
};


#endif
