/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccGetAgentInfoStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2017. 7. 1
 *   Description        :       get crypt statistics statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 1
#define DEBUG
#endif

#include "PccAgentStmt.h"

PccGetAgentInfoStmt::PccGetAgentInfoStmt(PccAgentCryptJobPool& job_pool,
                                         dgt_sint32 sess_id)
    : PccAgentStmt(job_pool), CurrIdx(-1) {
    memset(&AgentInfo, 0, sizeof(pcct_get_agent_info));
    SelectListDef = new DgcClass("select_list", 3);
    SelectListDef->addAttr(DGC_SB8, 0, "agent_id");
    SelectListDef->addAttr(DGC_SB8, 0, "last_update");
    SelectListDef->addAttr(DGC_SB4, 0, "sess_id");

    AgentInfo.agent_id = JobPool.agentID();
    AgentInfo.sess_id = sess_id;
}

PccGetAgentInfoStmt::~PccGetAgentInfoStmt() {}

dgt_sint32 PccGetAgentInfoStmt::execute(
    DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcExcept) {
    IsExecuted = 1;
    AgentInfo.last_update = JobPool.lastUpdate();
    CurrIdx = -1;
    return 0;
}

dgt_uint8* PccGetAgentInfoStmt::fetch() throw(DgcExcept) {
    if (IsExecuted == 0) {
        THROWnR(
            DgcDbNetExcept(DGC_EC_DN_INVALID_ST,
                           new DgcError(SPOS, "can't fetch without execution")),
            0);
    }
    if (CurrIdx < 0) {
        CurrIdx++;
        return (dgt_uint8*)&AgentInfo;
    }
    THROWnR(DgcDbNetExcept(NOT_FOUND, new DgcError(SPOS, "not found")), 0);
    return 0;
}
