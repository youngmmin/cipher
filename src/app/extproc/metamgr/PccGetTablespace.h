/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccGetTablespace
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 21
 *   Description        :       generate scripts
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_GET_TABLESPACE_H
#define PCC_GET_TABLESPACE_H


#include "PccMetaProcedure.h"


class PccGetTablespace : public PccMetaProcedure {
  private:
  protected:
  public:
	PccGetTablespace(const dgt_schar* name);
	virtual ~PccGetTablespace();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
