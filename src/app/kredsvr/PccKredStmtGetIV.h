/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmtGetIV
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_GET_IV_H
#define DGC_KRED_STMT_GET_IV_H

#include "PccKredStmt.h"
#include "PciMsgTypes.h"

class PccKredStmtGetIV : public PccKredStmt {
   private:
    dgt_uint32 NumRtnRows;
    pc_type_get_iv_out IVInfo;

   protected:
   public:
    PccKredStmtGetIV(DgcPhyDatabase* pdb, DgcSession* session,
                     DgcSqlTerm* stmt_term);
    virtual ~PccKredStmtGetIV();

    virtual dgt_sint32 execute(DgcMemRows* mrows = 0,
                               dgt_sint8 delete_flag = 1) throw(DgcLdbExcept,
                                                                DgcPdbExcept);
    virtual dgt_uint8* fetch() throw(DgcLdbExcept, DgcPdbExcept);
};

#endif
