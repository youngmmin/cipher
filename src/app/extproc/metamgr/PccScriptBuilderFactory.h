/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccScriptBuilderFactory
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 2. 29
 *   Description        :       script builder factory
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_SCRIPT_BUILDER_FACTORY_H
#define PCC_SCRIPT_BUILDER_FACTORY_H


#include "PccScriptBuilder.h"


class PccScriptBuilderFactory : public DgcObject {
  private:
	static PccScriptBuilderFactory*	Factory;

	PccScriptBuilder* scriptBuilder(DgcDatabase* db,DgcSession* sess,dgt_sint64 id,dgt_uint8 id_type) throw(DgcExcept);
	PccScriptBuilderFactory();
  protected:
  public:
	static const dgt_sint32 PCC_ID_TYPE_AGENT = 1;
	static const dgt_sint32 PCC_ID_TYPE_TABLE = 3;

	virtual ~PccScriptBuilderFactory();

	inline static PccScriptBuilder* getScriptBuilder(DgcDatabase* db,DgcSession* sess,dgt_sint64 id,dgt_uint8 id_type) throw(DgcExcept)
	{
		if (!Factory) Factory=new PccScriptBuilderFactory();
		return Factory->scriptBuilder(db,sess,id,id_type);
	};
};


#endif
