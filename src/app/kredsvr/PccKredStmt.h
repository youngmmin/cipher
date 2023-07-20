/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_H
#define DGC_KRED_STMT_H

#include "DgcSqlStmt.h"
#include "PcTableType.h"
#include "PccTableTypes.h"
#include "PciMsgTypes.h"

class PccKredStmt : public DgcSqlStmt {
   private:
   protected:
    DgcMemRows* UserVarRows;  // user variable rows
    DgcClass* SelectListDef;  // row definition for select list
    DgcSqlStmt* PrivStmt;     // privilege getting statement
    DgcLogger* TLOG;          // trace logger

    dgt_sint32 getPrivilege(pc_type_get_priv_in* priv_in,
                            pc_type_get_priv_out* priv_out,
                            pct_type_priv_request_hist* rqst_hist);

   public:
    PccKredStmt(DgcPhyDatabase* pdb, DgcSession* session,
                DgcSqlTerm* stmt_term);
    virtual ~PccKredStmt();

    inline dgt_void setTraceLog(DgcLogger* tlog) { TLOG = tlog; };

    virtual dgt_sint8 defineUserVars(DgcMemRows* mrows = 0) throw(DgcLdbExcept);
    virtual dgt_sint8 describe(DgcClass* def) throw(DgcLdbExcept);
    virtual DgcClass* fetchListDef() throw(DgcLdbExcept);
    virtual dgt_void dump(DgcBufferStream* bs);
};

#endif
