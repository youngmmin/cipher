/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccChangeScript
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 21
 *   Description        :       generate scripts
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_CHANGE_SCRIPT_H
#define PCC_CHANGE_SCRIPT_H


#include "PccMetaProcedure.h"


typedef struct {
	dgt_sint64	enc_tab_id;
	dgt_uint16	version_no;
	dgt_sint16	step_no;
	dgt_sint16	stmt_no;
	dgt_schar	script_text[64000];
} pc_type_change_script_in;

class PccChangeScript : public PccMetaProcedure {
  private:
	pc_type_change_script_in*	InRow;
  protected:
  public:
	PccChangeScript(const dgt_schar* name);
	virtual ~PccChangeScript();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};


#endif
