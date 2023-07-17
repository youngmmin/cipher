/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccGenScriptMig
 *   Implementor        :       mwpark
 *   Create Date        :       2015. 8. 14
 *   Description        :       generate migration scripts
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_GEN_SCRIPT_MIG_H
#define PCC_GEN_SCRIPT_MIG_H


#include "PccMetaProcedure.h"


class PccGenScriptMig : public PccMetaProcedure {
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
	PccGenScriptMig(const dgt_schar* name);
	virtual ~PccGenScriptMig();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
