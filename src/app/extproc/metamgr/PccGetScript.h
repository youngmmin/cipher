/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccGetScript
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 21
 *   Description        :       generate scripts
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_GET_SCRIPT_H
#define PCC_GET_SCRIPT_H


#include "PccMetaProcedure.h"


typedef struct {
	dgt_sint64	enc_tab_id;
	dgt_uint16	version_no;
	dgt_sint16	step_no;
	dgt_sint16	stmt_no;
} pc_type_get_script_in;


class PccGetScript : public PccMetaProcedure {
  private:
	pc_type_get_script_in*	InRow;
  protected:
  public:
	PccGetScript(const dgt_schar* name);
	virtual ~PccGetScript();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
