/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccPcfsGetStat
 *   Implementor        :       chchung
 *   Create Date        :       2018. 07. 17
 *   Description        :       get PCFS statistics
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_PCFS_GET_STAT_H
#define PFCC_PCFS_GET_STAT_H

#include "PfccAgentProcedure.h"

typedef struct {
    dgt_sint64 agent_id;
    dgt_uint16 pcfs_id;
    dgt_uint16 mount_type;
} pfcc_pcfs_get_stat_in;

class PfccPcfsGetStat : public PfccAgentProcedure {
   private:
    DgcCliStmt* CliStmt;

   protected:
   public:
    PfccPcfsGetStat(const dgt_schar* name, PfccAgentListener* agent_listener);
    virtual ~PfccPcfsGetStat();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 initialize() throw(DgcExcept);
    virtual dgt_sint32 execute() throw(DgcExcept);
    virtual dgt_sint32 fetch() throw(DgcExcept);
};

#endif
