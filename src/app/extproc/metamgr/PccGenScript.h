/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccGenScript
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 21
 *   Description        :       generate scripts
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_GEN_SCRIPT_H
#define PCC_GEN_SCRIPT_H


#include "PccMetaProcedure.h"


class PccGenScript : public PccMetaProcedure {
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
	PccGenScript(const dgt_schar* name);
	virtual ~PccGenScript();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
