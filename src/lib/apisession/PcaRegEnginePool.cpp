/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcaRegEngienPool
 *   Implementor        :       mwpark
 *   Create Date        :       2017. 8. 29.
 *   Description        :       petra cipher API regular engine pool
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcaRegEnginePool.h"

#include "DgcCRC64.h"

PcaRegEnginePool::PcaRegEnginePool() : RegEngineList(20) { isInitialize = 0; }

PcaRegEnginePool::~PcaRegEnginePool() {
    PccHashNode* hnp = 0;
    RegEngineList.rewind();
    while ((hnp = RegEngineList.nextNode())) {
        delete (PccRegExprSearchEngine*)hnp->value();
        hnp->setValue();
    }
}

PccRegExprSearchEngine* PcaRegEnginePool::getRegEngine(
    dgt_sint64 reg_engine_id) {
    if (isInitialize == 0) {
        // create decrypt regular engine
        dgt_sint64 key_id = 19901130;  // decrypt engine id - this number.. is
                                       // birthday of shson!
        PccRegExprSearchEngine* SearchEngine = new PccRegExprSearchEngine(0, 0);
        if (SearchEngine->addRegExpr(1, PPE_TAG_REG_EXPR, ErrMsg) < 0) {
            sprintf(ErrMsg, "decrypt_regular addRegExpr Failed[%s]",
                    PPE_TAG_REG_EXPR);
            return 0;
        }
        PccHashNode* hnp = RegEngineList.addNode(key_id, SearchEngine);
        if (hnp)
            isInitialize = 1;
        else {
            sprintf(ErrMsg, "put RegEngine Failed[%lld]", key_id);
            delete SearchEngine;  // two
        }
    }
    memset(ErrMsg, 0, sizeof(ErrMsg));
    // get crc value
    dgt_sint64 key_id = reg_engine_id;
    PccHashNode* hnp = RegEngineList.findNode(key_id);
    if (hnp) return (PccRegExprSearchEngine*)hnp->value();
    sprintf(ErrMsg, "not found RegEngine [%lld]", key_id);
    return 0;
}

PccRegExprSearchEngine* PcaRegEnginePool::putRegEngine(dgt_sint64 reg_engine_id,
                                                       dgt_schar* param) {
    memset(ErrMsg, 0, sizeof(ErrMsg));
    dgt_sint64 key_id = reg_engine_id;
    DgcBgrammer bg;
    dgt_schar* val = 0;
    if (bg.parse(param) < 0) {
        DgcExcept* e = EXCEPTnC;
        if (e) {
            DgcWorker::PLOG.tprintf(0, *e, "bgrammar parse failed:\n");
            delete e;
        }
        return 0;
    }
    dgt_sint32 NumRegExpr = 0;
    struct {
        dgt_uint16 col_no;
        dgt_schar* expr_string;
    } RegExprs[200];
    dgt_schar expr_string[32];
    dgt_sint32 col_no;
    for (col_no = 1;; col_no++) {
        dgt_sint32 expr_no;
        for (expr_no = 1;; expr_no++) {
            sprintf(expr_string, "regular.%d.%d", col_no, expr_no);
            if ((val = bg.getValue(expr_string))) {
                RegExprs[NumRegExpr].col_no = col_no;
                RegExprs[NumRegExpr++].expr_string = val;
            } else {
                break;
            }
        }
        if (expr_no == 1) break;
    }  // for end
    if (col_no == 1) {
        // no expression
        sprintf(ErrMsg, "no expression, check param");
        return 0;
    }
    PccRegExprSearchEngine* SearchEngine = new PccRegExprSearchEngine(0, 0);
    for (dgt_sint32 i = 0; i < NumRegExpr; i++) {
        if (SearchEngine->addRegExpr(RegExprs[i].col_no,
                                     RegExprs[i].expr_string, ErrMsg) < 0) {
            delete SearchEngine;
            return 0;
        }
    }
    PccHashNode* hnp = RegEngineList.addNode(key_id, SearchEngine);
    if (hnp) return (PccRegExprSearchEngine*)hnp->value();
    delete SearchEngine;
    sprintf(ErrMsg, "put RegEngine Failed[%lld]", reg_engine_id);
    return 0;
}
