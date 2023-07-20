/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccAgentTableTest
 *   Implementor        :       Mwpark
 *   Create Date        :       2013. 3. 25
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_AGENT_TABLE_TEST_H
#define PCC_AGENT_TABLE_TEST_H

#include "PccMetaProcedure.h"

typedef struct {
    dgt_sint64 db_agent_id;
} pct_type_db_agent_table_test_in;

class PccAgentTableTest : public PccMetaProcedure {
   private:
    pct_type_db_agent_table_test_in* InRow;

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
    PccAgentTableTest(const dgt_schar* name);
    virtual ~PccAgentTableTest();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
