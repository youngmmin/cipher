/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccGenScriptAddCol
 *   Implementor        :       mwpark
 *   Create Date        :       2014. 09. 20
 *   Description        :       generate scripts
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_GEN_SCRIPT_ADD_COL_H
#define PCC_GEN_SCRIPT_ADD_COL_H


#include "PccMetaProcedure.h"


class PccGenScriptAddCol : public PccMetaProcedure {
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
	PccGenScriptAddCol(const dgt_schar* name);
	virtual ~PccGenScriptAddCol();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
