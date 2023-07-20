/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmtGetKeySet
 *   Implementor        :       Jaehun
 *   Create Date        :       2015. 7. 15
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_GET_KEY_SET_H
#define DGC_KRED_STMT_GET_KEY_SET_H

#include "PccKredStmt.h"
#include "PccTableTypes.h"

class PccKredStmtGetKeySet : public PccKredStmt {
   private:
    pct_type_get_key_set_out KeySet;
    dgt_uint32 NumRtnRows;

   protected:
   public:
    PccKredStmtGetKeySet(DgcPhyDatabase* pdb, DgcSession* session,
                         DgcSqlTerm* stmt_term);
    virtual ~PccKredStmtGetKeySet();

    virtual dgt_sint32 execute(DgcMemRows* mrows = 0,
                               dgt_sint8 delete_flag = 1) throw(DgcLdbExcept,
                                                                DgcPdbExcept);
    virtual dgt_uint8* fetch() throw(DgcLdbExcept, DgcPdbExcept);
};

#endif
