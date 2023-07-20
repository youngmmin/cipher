/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccGetAgentStat
 *   Implementor        :       sonsuhun
 *   Create Date        :       2017. 07. 02
 *   Description        :       get EncTgtSys table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_GET_AGENT_STAT_H
#define PFCC_GET_AGENT_STAT_H

#include "PfccAgentProcedure.h"

typedef struct {
    dgt_sint64 agent_id;
    dgt_sint64 job_id;
} pfcc_get_agent_stat_in;

class PfccGetAgentStat : public PfccAgentProcedure {
   private:
    DgcCliStmt* CliStmt;

   protected:
   public:
    PfccGetAgentStat(const dgt_schar* name, PfccAgentListener* agent_listener);
    virtual ~PfccGetAgentStat();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 initialize() throw(DgcExcept);
    virtual dgt_sint32 execute() throw(DgcExcept);
    virtual dgt_sint32 fetch() throw(DgcExcept);
};

#endif
