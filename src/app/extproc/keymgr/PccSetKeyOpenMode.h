/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccSetKeyOpenMode
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 3
 *   Description        :       open keys
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_SET_KEY_OPEN_MODE_H
#define PCC_SET_KEY_OPEN_MODE_H

#include "DgcExtProcedure.h"
#include "DgcSqlHandle.h"

class PccSetKeyOpenMode : public DgcExtProcedure {
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
    PccSetKeyOpenMode(const dgt_schar* name);
    virtual ~PccSetKeyOpenMode();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
