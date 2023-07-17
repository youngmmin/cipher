/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccCreateRsaKey
 *   Implementor        :       mwpark
 *   Create Date        :       2017. 6. 22
 *   Description        :       
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_CREATE_RSA_KEY_H
#define PCC_CREATE_RSA_KEY_H


#include "DgcExtProcedure.h"


class PccCreateRsaKey : public DgcExtProcedure {
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
	PccCreateRsaKey(const dgt_schar* name);
	virtual ~PccCreateRsaKey();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
