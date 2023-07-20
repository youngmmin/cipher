/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmtOpenSess
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_OPEN_SESS_H
#define DGC_KRED_STMT_OPEN_SESS_H

#include "PccKredStmt.h"

class PccKredStmtOpenSess : public PccKredStmt {
   private:
    pc_type_open_sess_out SessOut;
    dgt_uint32 NumRtnRows;

   protected:
   public:
    PccKredStmtOpenSess(DgcPhyDatabase* pdb, DgcSession* session,
                        DgcSqlTerm* stmt_term);
    virtual ~PccKredStmtOpenSess();

    virtual dgt_sint32 execute(DgcMemRows* mrows = 0,
                               dgt_sint8 delete_flag = 1) throw(DgcLdbExcept,
                                                                DgcPdbExcept);
    virtual dgt_uint8* fetch() throw(DgcLdbExcept, DgcPdbExcept);
};

#endif
