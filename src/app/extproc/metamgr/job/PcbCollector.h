/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcbCollector
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCB_COLLECTOR_H
#define PCB_COLLECTOR_H

#include "PcbSelectStmt.h"
#include "PcbWorker.h"

class PcbCollector : public PcbWorker {
   private:
    PcbSelectStmt* SelectStmt;

   protected:
    virtual dgt_sint32 run() throw(DgcExcept);

   public:
    PcbCollector(PcbSelectStmt* select_stmt, PcbDataChunkPool* chunk_pool,
                 pct_type_worker* worker_ptr);
    virtual ~PcbCollector();
};

#endif
