/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccPcfsMount
 *   Implementor        :       chchung
 *   Create Date        :       2018. 07. 17
 *   Description        :       mount or unmount PCFS
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_PCFS_MOUNT_H
#define PFCC_PCFS_MOUNT_H

#include "PfccAgentProcedure.h"

typedef struct {
        dgt_sint64      agent_id;
        dgt_uint16      pcfs_id;
        dgt_uint16      mount_type;
} pfcc_pcfs_mount_in;

class PfccPcfsMount : public PfccAgentProcedure {
  private:
	DgcCliStmt*     CliStmt;
  protected:
  public:
	PfccPcfsMount(const dgt_schar* name, PfccAgentListener* agent_listener);
	virtual ~PfccPcfsMount();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 initialize() throw(DgcExcept);
	virtual dgt_sint32 execute() throw(DgcExcept);
	virtual dgt_sint32 fetch() throw(DgcExcept);
};

#endif
