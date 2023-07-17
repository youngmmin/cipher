/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccOpenKey
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 3
 *   Description        :       open keys
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_OPEN_KEY_H
#define PCC_OPEN_KEY_H


#include "DgcExtProcedure.h"


class PccOpenKey : public DgcExtProcedure {
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
	PccOpenKey(const dgt_schar* name);
	virtual ~PccOpenKey();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
