/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccGenScript2
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 21
 *   Description        :       generate scripts
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_GEN_SCRIPT2_H
#define PCC_GEN_SCRIPT2_H

#include "PccMetaProcedure.h"

class PccGenScript2 : public PccMetaProcedure {
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
    PccGenScript2(const dgt_schar* name);
    virtual ~PccGenScript2();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
