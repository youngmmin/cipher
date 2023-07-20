/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccAgentProcSvr
 *   Implementor        :       Jaehun
 *   Create Date        :       2017. 7. 1
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_CRYPT_STAT_COLLECTOR_H
#define PFCC_CRYPT_STAT_COLLECTOR_H

#include "DgcPetraWorker.h"
#include "PfccAgentProcSvr.h"
#include "PfccGetDirCryptStat.h"

class PfccCryptStatCollector : public DgcPetraWorker {
   private:
    dgt_sint32 CollectingInterval;
    PfccAgentListener* AgentListener;

    virtual dgt_void in() throw(DgcExcept);
    virtual dgt_sint32 run() throw(DgcExcept);
    virtual dgt_void out() throw(DgcExcept);

   protected:
   public:
    PfccCryptStatCollector(dgt_worker* wa, PfccAgentListener* agent_listener,
                           dgt_sint32 collecting_interval);
    virtual ~PfccCryptStatCollector();
};
#endif
