/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccGetCredentials
 *   Implementor        :       jhpark
 *   Create Date        :       2012. 4. 1
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_GET_CREDENTIALS
#define PCC_GET_CREDENTIALS


#include "DgcExtProcedure.h"

typedef struct
{
	dgt_sint32 errcode;
	dgt_schar  result[1024];
} pc_get_credentials_ret;


class PccGetCredentials : public DgcExtProcedure {
  private:
  protected:
  public:
	PccGetCredentials(const dgt_schar* name);
	virtual ~PccGetCredentials();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif /* PCC_GET_CREDENTIALS */
