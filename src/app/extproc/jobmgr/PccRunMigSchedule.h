/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccRunMigSchedule
 *   Implementor        :       mwpark
 *   Create Date        :       2015. 8. 14
 *   Description        :       run a migration schedule
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_RUN_MIG_SCHEDULE_H
#define PCC_RUN_MIG_SCHEDULE_H

#include "DgcExtProcedure.h"

class PccRunMigSchedule : public DgcExtProcedure {
   private:
   protected:
   public:
    PccRunMigSchedule(const dgt_schar* name);
    virtual ~PccRunMigSchedule();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
