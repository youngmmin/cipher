/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcaRegEnginePool
 *   Implementor        :       mwpark
 *   Create Date        :       2017. 8. 29.
 *   Description        :       petra cipher API regular engine pool
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCA_REG_ENGINE_POOL_H
#define PCA_REG_ENGINE_POOL_H

#include "PccHashTable.h"
#include "PccSearchEngineFactory.h"

class PcaRegEnginePool : public DgcObject {
  private :
	dgt_schar ErrMsg[1024];
	PccHashTable RegEngineList;
	dgt_sint8 isInitialize;
  protected:
  public:
	PcaRegEnginePool();
	virtual ~PcaRegEnginePool();
	dgt_schar* getErr() { return ErrMsg; }

	PccRegExprSearchEngine* getRegEngine(dgt_sint64 reg_engine_id);
	PccRegExprSearchEngine* putRegEngine(dgt_sint64 reg_engine_id, dgt_schar* param);
};

#endif
