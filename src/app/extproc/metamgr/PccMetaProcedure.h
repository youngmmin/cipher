/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccMetaProcedure
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 21
 *   Description        :       meta managing parent procedure
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_META_PROCEDURE_H
#define PCC_META_PROCEDURE_H


#include "DgcExtProcedure.h"
#include "PccScriptBuilder.h"


class PccMetaProcedure : public DgcExtProcedure {
  private:
  protected:
	static const dgt_sint32	PCC_ID_TYPE_AGENT = 1;
	static const dgt_sint32	PCC_ID_TYPE_TABLE = 3;
	static const dgt_sint32 PCC_MAX_SCRIPT_LEN = 64000;

	PccScriptBuilder* getScriptBuilder(dgt_sint64 id,dgt_uint8 id_type) throw(DgcExcept);
	dgt_sint32 getScript(dgt_sint64 enc_tab_id,dgt_uint16 version_no,dgt_sint16 step_no,dgt_sint16 stmt_no,DgcMemRows* rtn_rows) throw(DgcExcept);
  public:
	PccMetaProcedure(const dgt_schar* name);
	virtual ~PccMetaProcedure();
};


#endif
