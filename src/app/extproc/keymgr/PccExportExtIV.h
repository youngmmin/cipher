/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccExportExtIV
 *   Implementor        :       chchunt
 *   Create Date        :       2015. 8. 2
 *   Description        :       export an external iv
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_EXPORT_EXT_IV_H
#define PCC_EXPORT_EXT_IV_H

#include "DgcExtProcedure.h"

class PccExportExtIV : public DgcExtProcedure {
   private:
   protected:
    /*
            dgt_schar               ProcName[DGC_MAX_NAME_LEN+1];   // procedure
       name DgcDatabase*            Database;                       // database
            DgcSession*             Session;                        // session
            DgcCallStmt*            CallStmt;                       // call
       statement DgcMemRows*             BindRows;                       // bind
       rows DgcMemRows*             ReturnRows;                     // return
       rows
    */
   public:
    PccExportExtIV(const dgt_schar* name);
    virtual ~PccExportExtIV();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
