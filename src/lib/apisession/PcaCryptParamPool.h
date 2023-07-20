/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcaCryptParamPool
 *   Implementor        :       shson
 *   Create Date        :       2018. 11. 20.
 *   Description        :       petra cipher API crypt param pool
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCA_CRYPT_PARAM_POOL_H
#define PCA_CRYPT_PARAM_POOL_H

#include "PccHashTable.h"

class PcaCryptParamPool : public DgcObject {
   private:
    dgt_schar ErrMsg[1024];
    PccHashTable CryptParamList;

   protected:
   public:
    PcaCryptParamPool();
    virtual ~PcaCryptParamPool();
    dgt_schar* getErr() { return ErrMsg; }

    dgt_schar* getCryptParam(dgt_schar* crypt_param_name);
    dgt_schar* putCryptParam(dgt_schar* crypt_param_name, dgt_schar* param);
};

#endif
