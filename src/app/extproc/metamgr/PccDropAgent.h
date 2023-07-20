/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccDropAgent
 *   Implementor        :       Mwpark
 *   Create Date        :       2013. 3. 25
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_DROP_AGENT_H
#define PCC_DROP_AGENT_H

#include "PccMetaProcedure.h"

typedef struct {
    dgt_sint64 service_id;
    dgt_schar sys_uid[33];
    dgt_schar sys_passwd[33];
} pc_type_drop_agent_in;

class PccDropAgent : public PccMetaProcedure {
   private:
    pc_type_drop_agent_in* InRow;

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
    PccDropAgent(const dgt_schar* name);
    virtual ~PccDropAgent();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
