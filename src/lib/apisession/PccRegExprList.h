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
#ifndef PCC_REGEXPR_LIST_H
#define PCC_REGEXPR_LIST_H

#include <stdio.h>
#include <string.h>
#ifndef WIN32
#include <regex.h>
#else  // WIN32 else
#ifdef KERNEL_MODE
// not using in kernel_mode
#else  // KERNEL_MODE else
#include <regex>
#endif  // KERNEL_MODE end
#endif  // WIN32 end

#include "DgcObject.h"
#include "PtChunkObjectList.h"

#ifndef WIN32
typedef struct {
    dgt_schar exp[1024];
    regex_t reg;
} exp_type;
#else
typedef struct {
    dgt_schar exp[1024];
} exp_type;
#endif

class PccRegExprList : public DgcObject {
   private:
    static const dgt_sint32 ERR_BUF_SIZE = 1024;
    dgt_schar ErrBuffer[ERR_BUF_SIZE + 1];
    PtChunkObjectList ExprList;

   protected:
   public:
    PccRegExprList();
    virtual ~PccRegExprList();
    dgt_void rewind() { ExprList.rewind(); }
    exp_type* nextPttn() { return (exp_type*)ExprList.nextObject(); }
    dgt_sint32 compileStr(const dgt_schar* str, dgt_schar* err_string);
};

#endif
