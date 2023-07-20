/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccRunJob
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 3. 6
 *   Description        :       run a job
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_RUN_JOB_H
#define PCC_RUN_JOB_H

#include "DgcExtProcedure.h"

class PccRunJob : public DgcExtProcedure {
   private:
   protected:
   public:
    PccRunJob(const dgt_schar* name);
    virtual ~PccRunJob();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
