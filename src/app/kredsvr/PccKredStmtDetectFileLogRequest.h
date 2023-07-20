/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmtDetectFileLogRequest
 *   Implementor        :       mjkim
 *   Create Date        :       2019. 05. 29
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_DETECT_FILE_LOG_REQUEST_H
#define DGC_KRED_STMT_DETECT_FILE_LOG_REQUEST_H

#include "PccKredStmt.h"
#include "PciMsgTypes.h"

class PccKredStmtDetectFileLogRequest : public PccKredStmt {
   private:
    dgt_uint32 NumRtnRows;
    dgt_sint32 Result;

   protected:
   public:
    PccKredStmtDetectFileLogRequest(DgcPhyDatabase* pdb, DgcSession* session,
                                    DgcSqlTerm* stmt_term);
    virtual ~PccKredStmtDetectFileLogRequest();

    virtual dgt_sint32 execute(DgcMemRows* mrows = 0,
                               dgt_sint8 delete_flag = 1) throw(DgcLdbExcept,
                                                                DgcPdbExcept);
    virtual dgt_uint8* fetch() throw(DgcLdbExcept, DgcPdbExcept);
};

#endif
