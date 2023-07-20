/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcbUpdateStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCB_UPDATE_STMT_H
#define PCB_UPDATE_STMT_H

#include "PcbCipherTable.h"
#include "PcbDataChunk.h"
#include "PcbStmt.h"

class PcbUpdateStmt : public PcbStmt {
   private:
   protected:
   public:
    PcbUpdateStmt(PcbCipherTable* cipher_table, dgt_uint32 array_size);
    virtual ~PcbUpdateStmt();

    virtual dgt_sint32 initialize() throw(DgcExcept) = 0;
    virtual dgt_sint32 update(PcbDataChunk* data_chunk) throw(DgcExcept) = 0;
    virtual dgt_sint32 verifUpdate(dgt_uint32 partition_number) throw(
        DgcExcept) = 0;
};

#endif
