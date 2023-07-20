/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccImportKey
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 8
 *   Description        :       import keys - master & encryption keys and
encryption key signatue
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_IMPORT_KEY_H
#define PCC_IMPORT_KEY_H

#include "DgcExtProcedure.h"

class PccImportKey : public DgcExtProcedure {
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
    PccImportKey(const dgt_schar* name);
    virtual ~PccImportKey();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
