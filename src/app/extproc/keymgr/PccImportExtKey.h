/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccImportExtKey
 *   Implementor        :       Jaehun
 *   Create Date        :       2015. 8. 2
 *   Description        :       import an external key
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_IMPORT_EXT_KEY_H
#define PCC_IMPORT_EXT_KEY_H

#include "DgcExtProcedure.h"

class PccImportExtKey : public DgcExtProcedure {
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
    PccImportExtKey(const dgt_schar* name);
    virtual ~PccImportExtKey();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
