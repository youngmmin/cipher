/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmtLogRequest
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_LOG_REQUEST_H
#define DGC_KRED_STMT_LOG_REQUEST_H

#include "PccKredStmt.h"
#include "PciMsgTypes.h"

class PccKredStmtLogRequest : public PccKredStmt {
   private:
    pc_type_log_request_in RqstInfo;
    dgt_uint32 NumRtnRows;
    dgt_sint32 Result;

   protected:
   public:
    PccKredStmtLogRequest(DgcPhyDatabase* pdb, DgcSession* session,
                          DgcSqlTerm* stmt_term);
    virtual ~PccKredStmtLogRequest();

    virtual dgt_sint32 execute(DgcMemRows* mrows = 0,
                               dgt_sint8 delete_flag = 1) throw(DgcLdbExcept,
                                                                DgcPdbExcept);
    virtual dgt_uint8* fetch() throw(DgcLdbExcept, DgcPdbExcept);
};

#endif
