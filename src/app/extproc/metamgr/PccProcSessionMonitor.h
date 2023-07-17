/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccProcSessionMonitor
 *   Implementor        :       jhpark
 *   Create Date        :       2013. 3. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_PROC_SESSION_MONITOR
#define PCC_PROC_SESSION_MONITOR


#include "DgcExtProcedure.h"
#include "DgcDatabaseLink.h"

class PccProcSessionMonitor : public DgcExtProcedure {
  private:
	DgcDatabaseLink* DatabaseLink;
  protected:
  public:
	PccProcSessionMonitor(const dgt_schar* name);
	virtual ~PccProcSessionMonitor();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif /* PCC_PROC_SESSION_MONITOR */
