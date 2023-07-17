/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccGetDirCryptStat
 *   Implementor        :       sonsuhun
 *   Create Date        :       2017. 07. 02
 *   Description        :       get EncTgtSys table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_GET_DIR_CRYPT_STAT_H
#define PFCC_GET_DIR_CRYPT_STAT_H

#include "PfccAgentProcedure.h"

typedef struct {
	dgt_sint64 agent_id;
	dgt_sint64 job_id;
	dgt_sint64 enc_zone_id;
	dgt_sint64 enc_job_tgt_id;
} pfcc_get_dir_crypt_stat_in;

class PfccGetDirCryptStat : public PfccAgentProcedure {
  private:
  protected:
  public:
	PfccGetDirCryptStat(const dgt_schar* name, PfccAgentListener* agent_listener);
	virtual ~PfccGetDirCryptStat();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 initialize() throw(DgcExcept);
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
