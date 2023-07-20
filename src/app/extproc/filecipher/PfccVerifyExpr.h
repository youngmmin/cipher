/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccVerifyExpr
 *   Implementor        :       mjkim
 *   Create Date        :       2019. 07. 18
 *   Description        :       verify regular expression
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_VERIFY_EXPR_H
#define PFCC_VERIFY_EXPR_H

#include "DgcExtProcedure.h"

typedef struct {
    dgt_schar expr[1024];
    dgt_schar reg[4096];
} pfcc_verify_expr_in;

typedef struct {
    dgt_sint32 rtn_code;
    dgt_schar err_msg[1025];
} pfcc_verify_expr_out;

class PfccVerifyExpr : public DgcExtProcedure {
   private:
   protected:
   public:
    PfccVerifyExpr(const dgt_schar* name);
    virtual ~PfccVerifyExpr();
    virtual DgcExtProcedure* clone();
    virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif
