/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccGenScriptColAdmin
 *   Implementor        :       mwpark
 *   Create Date        :       2014. 12. 17
 *   Description        :       generate scripts
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_GEN_SCRIPT_COL_ADMIN_H
#define PCC_GEN_SCRIPT_COL_ADMIN_H


#include "PccMetaProcedure.h"


class PccGenScriptColAdmin : public PccMetaProcedure {
  private:
  protected:
/*
        dgt_schar               ProcName[DGC_MAX_NAME_LEN+1];   // procedure name
        DgcDatabase*            Database;                       // database
        DgcSession*             Session;                        // session
        DgcCallStmt*            CallStmt;                       // call statement
        DgcMemRows*             BindRows;                       // bind rows
        DgcMemRows*             ReturnRows;                     // return rows
*/
  public:
	PccGenScriptColAdmin(const dgt_schar* name);
	virtual ~PccGenScriptColAdmin();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
