/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccImportExtIV
 *   Implementor        :       Jaehun
 *   Create Date        :       2015. 8. 2
 *   Description        :       import an external iv
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_IMPORT_EXT_IV_H
#define PCC_IMPORT_EXT_IV_H

#include "DgcExtProcedure.h"

class PccImportExtIV : public DgcExtProcedure {
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
	PccImportExtIV(const dgt_schar* name);
	virtual ~PccImportExtIV();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
