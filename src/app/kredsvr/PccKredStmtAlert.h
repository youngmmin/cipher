/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmtAlert
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_ALERT_H
#define DGC_KRED_STMT_ALERT_H

#include "PccKredStmt.h"
#include "PciMsgTypes.h"

class PccKredStmtAlert : public PccKredStmt {
   private:
    dgt_uint32 NumRtnRows;
    dgt_sint32 Result;

   protected:
   public:
    PccKredStmtAlert(DgcPhyDatabase* pdb, DgcSession* session,
                     DgcSqlTerm* stmt_term);
    virtual ~PccKredStmtAlert();

    virtual dgt_sint32 execute(DgcMemRows* mrows = 0,
                               dgt_sint8 delete_flag = 1) throw(DgcLdbExcept,
                                                                DgcPdbExcept);
    virtual dgt_uint8* fetch() throw(DgcLdbExcept, DgcPdbExcept);
};

#endif
