/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccAgentCursor
 *   Implementor        :       Jaehun
 *   Create Date        :       2017. 6. 30
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccAgentCursor.h"

PccAgentCursor::PccAgentCursor() {
    UsedFlag = 0;
    AgentStmt = 0;
}

PccAgentCursor::~PccAgentCursor() {
    if (AgentStmt != 0) delete AgentStmt;
}

dgt_void PccAgentCursor::open(PccAgentStmt* agent_stmt) {
    if (AgentStmt != 0) delete AgentStmt;
    AgentStmt = agent_stmt;
    UsedFlag = 1;
}

dgt_void PccAgentCursor::close() {
    if (AgentStmt != 0) {
        delete AgentStmt;
        AgentStmt = 0;
    }
    UsedFlag = 0;
}

dgt_void PccAgentCursor::closeStmt() {
    if (AgentStmt != 0) {
        delete AgentStmt;
        AgentStmt = 0;
    }
}
