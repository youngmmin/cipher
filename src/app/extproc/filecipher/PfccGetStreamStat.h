/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccGetStreamStat
 *   Implementor        :       sonsuhun
 *   Create Date        :       2019. 07.05 
 *   Description        :       
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_GET_STREAM_STAT_H
#define PFCC_GET_STREAM_STAT_H

#include "PfccAgentProcedure.h"


class PfccGetStreamStat : public PfccAgentProcedure {
  private:
  protected:
  public:
	PfccGetStreamStat(const dgt_schar* name, PfccAgentListener* agent_listener);
	virtual ~PfccGetStreamStat();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 initialize() throw(DgcExcept);
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
