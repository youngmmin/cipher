/*******************************************************************
 *   File Type          :       File Cipher Agent classes declaration
 *   Classes            :       PccCryptManagerPool
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 18
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_CRYPT_MANAGER_POOL_H
#define PCC_CRYPT_MANAGER_POOL_H

#include "PccCryptManager.h"

class PccCryptManagerPool : public DgcObject {
  private:
	static const dgt_sint32	MAX_MANAGERS = 50;
	PccAgentCryptJobPool&	JobPool;
	PccCorePool&			CorePool;
	PccCryptManager*		Managers[MAX_MANAGERS];
	dgt_sint32			NumManagers;
  protected:
  public:
	PccCryptManagerPool(PccAgentCryptJobPool& job_pool, PccCorePool& core_pool);
	virtual ~PccCryptManagerPool();
	dgt_sint32 numManagers() { return NumManagers; }
	dgt_sint32 addManagers(dgt_sint32 num_managers=1, dgt_sint32 agent_mode=0, dgt_schar* enc_col_name=0, dgt_schar* header_flag=0, dgt_sint32 buffer_size=0) throw(DgcExcept);
	dgt_sint32 stopManagers(dgt_sint32 num_managers=1);
	dgt_sint32 cleanManagers(dgt_sint32 force_flag=0) throw(DgcExcept);
};

#endif
