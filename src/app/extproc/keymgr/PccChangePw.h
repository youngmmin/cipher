/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccChangePw
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 8
 *   Description        :       change password
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_CHANGE_PW_H
#define PCC_CHANGE_PW_H


#include "DgcExtProcedure.h"


class PccChangePw : public DgcExtProcedure {
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
	PccChangePw(const dgt_schar* name);
	virtual ~PccChangePw();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
