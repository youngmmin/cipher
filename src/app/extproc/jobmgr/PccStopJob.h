/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccStopJob
 *   Implementor        :       mwpark
 *   Create Date        :       2012. 08. 14 
 *   Description        :       stop a job
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_STOP_JOB_H
#define PCC_STOP_JOB_H


#include "DgcExtProcedure.h"


class PccStopJob : public DgcExtProcedure {
  private:
  protected:
  public:
	PccStopJob(const dgt_schar* name);
	virtual ~PccStopJob();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
