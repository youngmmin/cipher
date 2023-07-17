/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcaRsaKeyPool
 *   Implementor        :       mwpark
 *   Create Date        :       2019. 04. 30.
 *   Description        :       petra cipher API rsa key zone
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCA_ENC_RSA_KEY_POOL_H
#define PCA_ENC_RSA_KEY_POOL_H

#include "PccHashTable.h"

class PcaRsaKeyPool : public DgcObject {
  private :
	dgt_schar ErrMsg[1024];
	PccHashTable RsaKeyList;
  protected:
  public:
	PcaRsaKeyPool();
	virtual ~PcaRsaKeyPool();
	dgt_schar* getErr() { return ErrMsg; }

	dgt_schar* getRsaKey(dgt_schar* key_name);
	dgt_schar* putRsaKey(dgt_schar* key_name, dgt_schar* key_string);
};

#endif
