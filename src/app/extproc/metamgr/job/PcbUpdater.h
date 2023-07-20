/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcbUpdater
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCB_UPDATER_H
#define PCB_UPDATER_H

#include "PcbUpdateStmt.h"
#include "PcbWorker.h"

class PcbUpdater : public PcbWorker {
   private:
    PcbUpdateStmt* UpdateStmt;

   protected:
    dgt_sint32 run() throw(DgcExcept);

   public:
    PcbUpdater(PcbUpdateStmt* update_stmt, PcbDataChunkPool* chunk_pool,
               pct_type_worker* worker_ptr);
    virtual ~PcbUpdater();
};

#endif
