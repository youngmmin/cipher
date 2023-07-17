/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccSetAgentParam
 *   Implementor        :       sonsuhun
 *   Create Date        :       2017. 07. 02
 *   Description        :       get EncTgtSys table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_SET_AGENT_PARAM_H
#define PFCC_SET_AGENT_PARAM_H

#include "PfccAgentProcedure.h"

typedef struct {
	dgt_sint64 agent_id;
	dgt_sint64 job_id;
} pfct_set_agent_param_in;

class PfccSetAgentParam : public PfccAgentProcedure {
  private:
  protected:
  public:
	PfccSetAgentParam(const dgt_schar* name, PfccAgentListener* agent_listener);
	virtual ~PfccSetAgentParam();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 initialize() throw(DgcExcept);
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
