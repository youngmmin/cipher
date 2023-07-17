/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccRunSchedule
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 3. 6
 *   Description        :       run a schedule
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_RUN_SCHEDULE_H
#define PCC_RUN_SCHEDULE_H


#include "DgcExtProcedure.h"


class PccRunSchedule : public DgcExtProcedure {
  private:
  protected:
  public:
	PccRunSchedule(const dgt_schar* name);
	virtual ~PccRunSchedule();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
