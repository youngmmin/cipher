/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmtGetRegEngine
 *   Implementor        :       mwpark
 *   Create Date        :       2017. 08. 29
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_GET_REG_ENGINE_H
#define DGC_KRED_STMT_GET_REG_ENGINE_H

#include "PccKredStmt.h"
#include "PccTableTypes.h"
#include "PciMsgTypes.h"

class PccKredStmtGetRegEngine : public PccKredStmt {
   private:
    dgt_uint32 NumRtnRows;
    dgt_schar* ResultParam;

   protected:
   public:
    PccKredStmtGetRegEngine(DgcPhyDatabase* pdb, DgcSession* session,
                            DgcSqlTerm* stmt_term);
    virtual ~PccKredStmtGetRegEngine();

    virtual dgt_sint32 execute(DgcMemRows* mrows = 0,
                               dgt_sint8 delete_flag = 1) throw(DgcLdbExcept,
                                                                DgcPdbExcept);
    virtual dgt_uint8* fetch() throw(DgcLdbExcept, DgcPdbExcept);
};

#endif
