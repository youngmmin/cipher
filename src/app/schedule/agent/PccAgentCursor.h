/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccAgentCursor
 *   Implementor        :       Jaehun
 *   Create Date        :       2017. 6. 30
 *   Description        :       
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_AGENT_CURSOR_H
#define PCC_AGENT_CURSOR_H

#include "PccAgentStmt.h"

class PccAgentCursor : public DgcObject {
  private:
	dgt_sint8	UsedFlag;		// used flag
	PccAgentStmt*	AgentStmt;		// agent statement
  protected:
  public:
	PccAgentCursor();
	virtual ~PccAgentCursor();

	inline dgt_sint8	usedFlag() { return UsedFlag; };
	inline PccAgentStmt*	agentStmt() { return AgentStmt; };

	dgt_void	open(PccAgentStmt* agent_stmt);
	dgt_void	close();
	dgt_void	closeStmt();
};


#endif
