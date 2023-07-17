/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccProcSessSqlText
 *   Implementor        :       jhpark
 *   Create Date        :       2013. 3. 27
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_PROC_SESS_SQL_TEXT
#define PCC_PROC_SESS_SQL_TEXT


#include "DgcExtProcedure.h"
#include "DgcDatabaseLink.h"

class PccProcSessSqlText : public DgcExtProcedure {
  private:
	DgcDatabaseLink* DatabaseLink;
  protected:
  public:
	PccProcSessSqlText(const dgt_schar* name);
	virtual ~PccProcSessSqlText();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif /* PCC_PROC_SESS_SQL_TEXT */
