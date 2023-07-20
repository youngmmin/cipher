/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PccRunMigVerify
 *   Implementor        :       mwpark
 *   Create Date        :       2015. 8. 14
 *   Description        :       run a migration verify
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_RUN_MIG_VERIFY_H
#define PCC_RUN_MIG_VERIFY_H

#include "DgcExtProcedure.h"

class PccRunMigVerify : public DgcExtProcedure {
   private:
   protected:
   public:
    PccRunMigVerify(const dgt_schar* name);
    virtual ~PccRunMigVerify();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
