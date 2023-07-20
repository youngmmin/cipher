/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccExportKey
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 8
 *   Description        :       export keys - master & encryption keys and
encryption key signatue
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_EXPORT_KEY_H
#define PCC_EXPORT_KEY_H

#include "DgcExtProcedure.h"

class PccExportKey : public DgcExtProcedure {
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
    PccExportKey(const dgt_schar* name);
    virtual ~PccExportKey();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
