/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccCreateKey
 *   Implementor        :       Jaehun
 *   Create Date        :       2009. 7. 8
 *   Description        :       create keys - master & encryption keys and
encryption key signatue
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_CREATE_KEY_H
#define PCC_CREATE_KEY_H

#include "DgcExtProcedure.h"

class PccCreateKey : public DgcExtProcedure {
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
    PccCreateKey(const dgt_schar* name);
    virtual ~PccCreateKey();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
