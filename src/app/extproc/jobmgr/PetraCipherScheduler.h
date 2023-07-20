/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PetraCipherScheduler
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PETRA_CIPHER_SCHEDULER_H
#define PETRA_CIPHER_SCHEDULER_H

#include "DgcPetraWorker.h"
#include "PccTableTypes.h"

class PetraCipherScheduler : public DgcPetraWorker {
   private:
    dgt_sint64 ScheduleID;
    DgcTableSegment* ScheduleSeg;
    DgcRowRef AllScheduleRows;
    pct_type_schedule* ScheduleRowPtr;

    dgt_sint32 startSchedule(pct_type_schedule* schedule) throw(DgcExcept);

    virtual dgt_void in() throw(DgcExcept);
    virtual dgt_sint32 run() throw(DgcExcept);
    virtual dgt_void out() throw(DgcExcept);

   protected:
   public:
    PetraCipherScheduler(dgt_worker* wa);
    virtual ~PetraCipherScheduler();

    dgt_sint32 initialize() throw(DgcExcept);
};

#endif
