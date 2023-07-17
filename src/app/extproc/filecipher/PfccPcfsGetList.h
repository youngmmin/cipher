/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccPcfsGetList
 *   Implementor        :       chchung
 *   Create Date        :       2018. 07. 17
 *   Description        :       get PCFS list
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_PCFS_GET_LIST_H
#define PFCC_PCFS_GET_LIST_H

#include "PfccAgentProcedure.h"

class PfccPcfsGetList : public PfccAgentProcedure {
  private:
	DgcCliStmt*     CliStmt;
  protected:
  public:
	PfccPcfsGetList(const dgt_schar* name, PfccAgentListener* agent_listener);
	virtual ~PfccPcfsGetList();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 initialize() throw(DgcExcept);
	virtual dgt_sint32 execute() throw(DgcExcept);
	virtual dgt_sint32 fetch() throw(DgcExcept);
};

#endif
