/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccCreateExtKey
 *   Implementor        :       Jaehun
 *   Create Date        :       2009. 7. 8
 *   Description        :       create keys - master & encryption keys and encryption key signatue
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_CREATE_EXT_KEY_H
#define PCC_CREATE_EXT_KEY_H


#include "DgcExtProcedure.h"


class PccCreateExtKey : public DgcExtProcedure {
  private:
	static const dgt_sint32 MAX_EXT_KEY_LEN = 1024;
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
	PccCreateExtKey(const dgt_schar* name);
	virtual ~PccCreateExtKey();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
