/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccGenScript
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 4
 *   Description        :       generate scripts
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_RUN_SCRIPT_H
#define PCC_RUN_SCRIPT_H

#include "PccMetaProcedure.h"

typedef struct {
    dgt_sint64 enc_tab_id;
    dgt_uint16 version_no;
    dgt_sint16 step_no;
    dgt_sint16 stmt_no;
} dgt_run_script_in;

class PccRunScript : public PccMetaProcedure {
   private:
    dgt_run_script_in* InRow;

   protected:
   public:
    PccRunScript(const dgt_schar* name);
    virtual ~PccRunScript();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
