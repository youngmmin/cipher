/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccEncrypt
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 3. 6
 *   Description        :       encrypt
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_ENCRYPT_H
#define PCC_ENCRYPT_H


#include "DgcExtProcedure.h"


class PccEncrypt : public DgcExtProcedure {
  private:
  protected:
  public:
	PccEncrypt(const dgt_schar* name);
	virtual ~PccEncrypt();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
