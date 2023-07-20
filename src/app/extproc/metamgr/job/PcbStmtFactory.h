/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcbStmtFactory
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCB_STMT_FACTORY_H
#define PCB_STMT_FACTORY_H

#include "PcbCipherTable.h"
#include "PcbSelectStmt.h"
#include "PcbUpdateStmt.h"

class PcbStmtFactory : public DgcObject {
   private:
    static PcbStmtFactory* StmtFactory;
    PcbStmtFactory();
    PcbSelectStmt* selectStmt(PcbCipherTable* cipher_table,
                              dgt_uint32 array_size) throw(DgcExcept);
    PcbUpdateStmt* updateStmt(PcbCipherTable* cipher_table,
                              dgt_uint32 array_size) throw(DgcExcept);
    PcbUpdateStmt* verifUpdateStmt(dgt_sint64 job_id,
                                   PcbCipherTable* cipher_table,
                                   dgt_uint32 array_size) throw(DgcExcept);

   protected:
   public:
    virtual ~PcbStmtFactory();

    static inline PcbSelectStmt* getSelectStmt(
        PcbCipherTable* cipher_table,
        dgt_uint32 array_size = 0) throw(DgcExcept) {
        if (!StmtFactory) StmtFactory = new PcbStmtFactory();
        return StmtFactory->selectStmt(cipher_table, array_size);
    };

    static inline PcbUpdateStmt* getUpdateStmt(
        PcbCipherTable* cipher_table,
        dgt_uint32 array_size = 0) throw(DgcExcept) {
        if (!StmtFactory) StmtFactory = new PcbStmtFactory();
        return StmtFactory->updateStmt(cipher_table, array_size);
    };

    static inline PcbUpdateStmt* getVerifUpdateStmt(
        dgt_sint64 job_id, PcbCipherTable* cipher_table,
        dgt_uint32 array_size = 0) throw(DgcExcept) {
        if (!StmtFactory) StmtFactory = new PcbStmtFactory();
        return StmtFactory->verifUpdateStmt(job_id, cipher_table, array_size);
    };
};

#endif
