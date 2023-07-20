/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccAgentTest
 *   Implementor        :       Mwpark
 *   Create Date        :       2013. 03. 25
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccAgentTest.h"

#include "DgcOracleConnection.h"

PccAgentTest::PccAgentTest(const dgt_schar* name) : PccMetaProcedure(name) {}

PccAgentTest::~PccAgentTest() {}

DgcExtProcedure* PccAgentTest::clone() { return new PccAgentTest(procName()); }

typedef struct {
    dgt_sint32 result_code;
    dgt_schar result_msg[1024];
} pct_type_db_agent_test_out;

dgt_sint32 PccAgentTest::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    if (!(InRow = (pct_type_db_agent_test_in*)BindRows->data())) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "no input row")),
                -1);
    }
    if (ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    pct_type_db_agent_test_out out_param;
    memset(&out_param, 0, sizeof(pct_type_db_agent_test_out));

    PccScriptBuilder* cipher_builder =
        getScriptBuilder(InRow->db_agent_id, PCC_ID_TYPE_AGENT);
    if (!cipher_builder) {
        ATHROWnR(DgcError(SPOS, "getScriptBuilder failed."), -1);
    }
    if (cipher_builder->agentTest(InRow->db_agent_id, ReturnRows) < 0) {
        delete cipher_builder;
        DgcExcept* e = EXCEPTnC;
        if (e) {
            RTHROWnR(e, DgcError(SPOS, "agentTest Failed"), -1);
        }
        return 0;
    }
    ReturnRows->reset();
    ReturnRows->add();
    ReturnRows->next();
    memset(ReturnRows->data(), 0, ReturnRows->rowSize());
    sprintf(out_param.result_msg, "%s", (dgt_schar*)"Agent Test Successfully");
    out_param.result_code = 7;
    memcpy(ReturnRows->data(), &out_param, sizeof(pct_type_db_agent_test_out));
    ReturnRows->rewind();
    return 0;
}
