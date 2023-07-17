/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccCreateExtIV
 *   Implementor        :       Jaehun
 *   Create Date        :       2009. 7. 8
 *   Description        :       create keys - master & encryption keys and encryption key signatue
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_CREATE_EXT_IV_H
#define PCC_CREATE_EXT_IV_H


#include "DgcExtProcedure.h"


class PccCreateExtIV : public DgcExtProcedure {
  private:
	static const dgt_sint32 MAX_EXT_IV_LEN = 1024;
	static const dgt_sint32 MAX_EXT_SIGN_LEN = 99;
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
	PccCreateExtIV(const dgt_schar* name);
	virtual ~PccCreateExtIV();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
