/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccRegExprList
 *   Implementor        :       mwpark
 *   Create Date        :       2017. 8. 02
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------
********************************************************************/

#include "PccRegExprList.h"

PccRegExprList::PccRegExprList() : ExprList(sizeof(exp_type)) {}

PccRegExprList::~PccRegExprList() {
#ifndef WIN32
    exp_type* curr_preg;
    ExprList.rewind();
    while ((curr_preg = (exp_type*)ExprList.nextObject()))
        regfree(&curr_preg->reg);
#endif
}

dgt_sint32 PccRegExprList::compileStr(const dgt_schar* str,
                                      dgt_schar* err_string) {
    dgt_sint32 errcode;
    exp_type* curr_preg = (exp_type*)ExprList.getObject();
    if (curr_preg) {
        memset(curr_preg, 0, sizeof(exp_type));
        memcpy(curr_preg->exp, str, strlen(str));
#ifndef WIN32
        regex_t tmp_preg;
        if ((errcode = regcomp(&tmp_preg, str, REG_EXTENDED))) {
            memset(ErrBuffer, 0, ERR_BUF_SIZE + 1);
            regerror(errcode, &tmp_preg, ErrBuffer, ERR_BUF_SIZE);
            sprintf(err_string, "pattern[%s] compilation failed:[%s]", str,
                    ErrBuffer);
            return -1;
        }
        memcpy(&curr_preg->reg, &tmp_preg, sizeof(regex_t));
#endif
        return 1;
    }
#ifndef Win32
    sprintf(err_string, "out of buffer for [%s]\n", str);
    return -2;
#else
    return 1;
#endif
}
