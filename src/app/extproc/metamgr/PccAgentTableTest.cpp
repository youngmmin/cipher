/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccAgentTableTest
 *   Implementor        :       Mwpark
 *   Create Date        :       2013. 03. 25
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccAgentTableTest.h"

#include "DgcOracleConnection.h"

PccAgentTableTest::PccAgentTableTest(const dgt_schar* name)
    : PccMetaProcedure(name) {}

PccAgentTableTest::~PccAgentTableTest() {}

DgcExtProcedure* PccAgentTableTest::clone() {
    return new PccAgentTableTest(procName());
}

typedef struct {
    dgt_uint16 parallel_degree;
    dgt_sint8 domain_index;
    dgt_sint8 data_type;
    dgt_sint8 algorithm;
    dgt_schar result_msg[1024];
} pct_type_db_agent_table_test_out;

dgt_sint32 PccAgentTableTest::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    if (!(InRow = (pct_type_db_agent_table_test_in*)BindRows->data())) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "no input row")),
                -1);
    }
    if (ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    pct_type_db_agent_table_test_out out_param;
    memset(&out_param, 0, sizeof(pct_type_db_agent_table_test_out));

    PccScriptBuilder* cipher_builder =
        getScriptBuilder(InRow->db_agent_id, PCC_ID_TYPE_AGENT);
    if (!cipher_builder) {
        ATHROWnR(DgcError(SPOS, "getScriptBuilder failed."), -1);
    }
    ReturnRows->reset();
    if (cipher_builder->agentTableTest(InRow->db_agent_id, ReturnRows) < 0) {
        delete cipher_builder;
        DgcExcept* e = EXCEPTnC;
        if (e) {
            RTHROWnR(e, DgcError(SPOS, "agentTableTest Failed"), -1);
        }
        return 0;
    }
    ReturnRows->rewind();
    return 0;
}
