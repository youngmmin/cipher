/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccGetTargetList
 *   Implementor        :       sonsuhun
 *   Create Date        :       2018. 03.27 
 *   Description        :       get EncTgtSys table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_GET_TARGET_LIST_H
#define PFCC_GET_TARGET_LIST_H

#include "PfccAgentProcedure.h"


class PfccGetTargetList : public PfccAgentProcedure {
  private:
	DgcCliStmt*     CliStmt;
  protected:
  public:
	PfccGetTargetList(const dgt_schar* name, PfccAgentListener* agent_listener);
	virtual ~PfccGetTargetList();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 initialize() throw(DgcExcept);
	virtual dgt_sint32 execute() throw(DgcExcept);
	virtual dgt_sint32 fetch() throw(DgcExcept);
};


#endif
