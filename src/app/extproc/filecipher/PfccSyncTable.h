/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccSyncTable
 *   Implementor        :       mjkim
 *   Create Date        :       2018. 11. 06
 *   Description        :       sync table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_SYNC_TABLE_H
#define PFCC_SYNC_TABLE_H

#include "DgcExtProcedure.h"

typedef struct {
	dgt_schar  table_name[256];
	dgt_sint64 artificial_id;
	dgt_sint8  delete_flag;
} pfcc_sync_table_in;

typedef struct {
	dgt_sint64 enc_job_id;
	dgt_sint32 agent_last_update;
} pfcc_sync_table_out;

typedef struct {
	dgt_sint64 agent_id;
	dgt_sint64 enc_job_id;
} pfcc_set_agent_param_in;

class PfccSyncTable : public DgcExtProcedure {
  private:
	pfcc_sync_table_in* param_in;
	pfcc_sync_table_out* param_out;
  protected:
  public:
	PfccSyncTable(const dgt_schar* name);
	virtual ~PfccSyncTable();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
