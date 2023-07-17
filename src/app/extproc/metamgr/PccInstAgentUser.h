/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccInstAgentUser
 *   Implementor        :       Mwpark
 *   Create Date        :       2013. 3. 25
 *   Description        :      
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_INST_AGENT_USER_H
#define PCC_INST_AGENT_USER_H


#include "PccMetaProcedure.h"


typedef struct {
        dgt_sint64      db_agent_id;
        dgt_schar       sys_uid[33];
        dgt_schar       sys_passwd[33];
        dgt_schar       agent_uid[33];
        dgt_schar       agent_passwd[33];
        dgt_schar       soha_home[512];
	dgt_uint8	inst_mode;
} pc_type_inst_agent_user_in;

class PccInstAgentUser : public PccMetaProcedure {
  private:
	pc_type_inst_agent_user_in*	InRow;
  protected:
/*
        dgt_schar               ProcName[DGC_MAX_NAME_LEN+1];   // procedure name
        DgcDatabase*            Database;                       // database
        DgcSession*             Session;                        // session
        DgcCallStmt*            CallStmt;                       // call statement
        DgcMemRows*             BindRows;                       // bind rows
        DgcMemRows*             ReturnRows;                     // return rows
*/
  public:
	PccInstAgentUser(const dgt_schar* name);
	virtual ~PccInstAgentUser();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
