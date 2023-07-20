/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PfccDeleteCryptStat
 *   Implementor        :       mjkim
 *   Create Date        :       2018. 07. 19
 *   Description        :       delete pfct_crypt_stat_temp table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PfccDeleteCryptStat.h"

#include "DgcSqlHandle.h"

PfccDeleteCryptStat::PfccDeleteCryptStat(const dgt_schar* name)
    : DgcExtProcedure(name) {}

PfccDeleteCryptStat::~PfccDeleteCryptStat() {}

DgcExtProcedure* PfccDeleteCryptStat::clone() {
    return new PfccDeleteCryptStat(procName());
}

dgt_sint32 PfccDeleteCryptStat::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }

    pfcc_delete_crypt_stat_in* stat_in =
        (pfcc_delete_crypt_stat_in*)BindRows->data();

    DgcSqlHandle sql_handle(DgcDbProcess::sess());
    dgt_schar sql_text[256];
    memset(sql_text, 0, 256);
    sprintf(sql_text, "delete pfct_crypt_stat_temp where dir_id = %lld ",
            stat_in->dir_id);

    if (sql_handle.execute(sql_text) < 0) {
        ATHROWnR(DgcError(SPOS, "execute failed"), -1);
    }

    dgt_sint32 rtn = 0;
    ReturnRows->reset();
    ReturnRows->add();
    ReturnRows->next();
    *(ReturnRows->data()) = 0;
    dg_memcpy(ReturnRows->data(), &rtn, sizeof(dgt_sint32));
    ReturnRows->rewind();
    return 0;
}
