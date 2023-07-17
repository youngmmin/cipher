/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccGetKey
 *   Implementor        :       mwpark
 *   Create Date        :       2014. 07. 30
 *   Description        :       get keys 
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_GET_KEY_H
#define PCC_GET_KEY_H


#include "DgcExtProcedure.h"


class PccGetKey : public DgcExtProcedure {
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
	PccGetKey(const dgt_schar* name);
	virtual ~PccGetKey();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
