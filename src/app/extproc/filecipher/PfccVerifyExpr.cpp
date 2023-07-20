/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PfccVerifyExpr
 *   Implementor        :       mjkim
 *   Create Date        :       2019. 07. 18
 *   Description        :       verify regular expression
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PfccVerifyExpr.h"

#include <regex.h>

PfccVerifyExpr::PfccVerifyExpr(const dgt_schar* name) : DgcExtProcedure(name) {}

PfccVerifyExpr::~PfccVerifyExpr() {}

DgcExtProcedure* PfccVerifyExpr::clone() {
    return new PfccVerifyExpr(procName());
}

dgt_sint32 PfccVerifyExpr::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    pfcc_verify_expr_in* param_in = (pfcc_verify_expr_in*)BindRows->data();
    if (!param_in)
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "no input row")),
                -1);

    regex_t regex;
    dgt_sint32 ret = 0;
    if ((ret = regcomp(&regex, (dgt_schar*)param_in->expr, REG_EXTENDED)) ==
        0) {
        regmatch_t pttn_match[1];
        if ((ret = regexec(&regex, param_in->reg, 1, pttn_match, 0)) == 0) {
            if ((pttn_match[0].rm_eo - pttn_match[0].rm_so) !=
                (dgt_sint32)strlen(param_in->reg)) {
                ret = REG_NOMATCH;
            }
        }
    }

    ReturnRows->reset();
    ReturnRows->add();
    ReturnRows->next();

    pfcc_verify_expr_out param_out;
    param_out.rtn_code = ret;
    regerror(ret, &regex, param_out.err_msg, 100);
    memcpy(ReturnRows->data(), &param_out, sizeof(pfcc_verify_expr_out));
    ReturnRows->rewind();
    return 0;
}
