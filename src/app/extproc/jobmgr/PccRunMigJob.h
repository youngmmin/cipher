/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccRunMigJob
 *   Implementor        :       mwpark
 *   Create Date        :       2015. 8. 14 
 *   Description        :       run a migration job
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_RUN_MIG_JOB_H
#define PCC_RUN_MIG_JOB_H


#include "DgcExtProcedure.h"


class PccRunMigJob : public DgcExtProcedure {
  private:
  protected:
  public:
	PccRunMigJob(const dgt_schar* name);
	virtual ~PccRunMigJob();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
