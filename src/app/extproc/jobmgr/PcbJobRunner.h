/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcbJobRunner
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCB_JOB_RUNNER_H
#define PCB_JOB_RUNNER_H


#include "DgcExcept.h"


class PcbJobRunner : public DgcObject {
  private:
	static dgt_sint32 startJob(dgt_schar* arg1,dgt_schar* arg2=0) throw(DgcExcept);
	static dgt_sint32 startMigVerify(dgt_schar* arg1) throw(DgcExcept);
  protected:
  public:
	static dgt_sint32 startJob(dgt_sint64 job_id) throw(DgcExcept);
	static dgt_sint32 startJob(dgt_sint64 enc_tab_id,dgt_sint16 target_step) throw(DgcExcept);
	static dgt_sint32 startMigVerify(dgt_sint64 job_id) throw(DgcExcept);
};


#endif
