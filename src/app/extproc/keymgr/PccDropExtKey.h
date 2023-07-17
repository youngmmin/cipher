/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccDropExtKey
 *   Implementor        :       Jaehun
 *   Create Date        :       2015. 8. 2
 *   Description        :       drop external key
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_DROP_EXT_KEY_H
#define PCC_DROP_EXT_KEY_H

#include "DgcExtProcedure.h"

class PccDropExtKey : public DgcExtProcedure {
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
	PccDropExtKey(const dgt_schar* name);
	virtual ~PccDropExtKey();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
