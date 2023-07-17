/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccRunVerifySchedule
 *   Implementor        :       mwpark
 *   Create Date        :       2015. 8. 14
 *   Description        :       run a verify schedule
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_RUN_VERIFY_SCHEDULE_H
#define PCC_RUN_VERIFY_SCHEDULE_H


#include "DgcExtProcedure.h"


class PccRunVerifySchedule : public DgcExtProcedure {
  private:
  protected:
  public:
	PccRunVerifySchedule(const dgt_schar* name);
	virtual ~PccRunVerifySchedule();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
