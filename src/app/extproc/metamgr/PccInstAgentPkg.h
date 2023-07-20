/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccInstAgentPkg
 *   Implementor        :       Mwpark
 *   Create Date        :       2013. 3. 25
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_INST_AGENT_PKG_H
#define PCC_INST_AGENT_PKG_H

#include "PccMetaProcedure.h"

typedef struct {
    dgt_sint64 db_agent_id;
} pc_type_inst_agent_pkg_in;

class PccInstAgentPkg : public PccMetaProcedure {
   private:
    pc_type_inst_agent_pkg_in* InRow;

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
    PccInstAgentPkg(const dgt_schar* name);
    virtual ~PccInstAgentPkg();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
