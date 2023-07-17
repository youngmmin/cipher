/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccRunMigVerifySchedule
 *   Implementor        :       mwpark
 *   Create Date        :       2015. 8. 14
 *   Description        :       run a mig verify schedule
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_RUN_MIG_VERIFY_SCHEDULE_H
#define PCC_RUN_MIG_VERIFY_SCHEDULE_H


#include "DgcExtProcedure.h"


class PccRunMigVerifySchedule : public DgcExtProcedure {
  private:
  protected:
  public:
	PccRunMigVerifySchedule(const dgt_schar* name);
	virtual ~PccRunMigVerifySchedule();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
