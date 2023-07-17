/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccRunVerify
 *   Implementor        :       mwpark
 *   Create Date        :       2015. 8. 14 
 *   Description        :       run a verify
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_RUN_VERIFY_H
#define PCC_RUN_VERIFY_H


#include "DgcExtProcedure.h"


class PccRunVerify : public DgcExtProcedure {
  private:
  protected:
  public:
	PccRunVerify(const dgt_schar* name);
	virtual ~PccRunVerify();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
