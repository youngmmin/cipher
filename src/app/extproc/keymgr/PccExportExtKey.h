/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccExportExtKey
 *   Implementor        :       chchunt
 *   Create Date        :       2015. 8. 2
 *   Description        :       export an external key
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_EXPORT_EXT_KEY_H
#define PCC_EXPORT_EXT_KEY_H

#include "DgcExtProcedure.h"

class PccExportExtKey : public DgcExtProcedure {
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
	PccExportExtKey(const dgt_schar* name);
	virtual ~PccExportExtKey();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
