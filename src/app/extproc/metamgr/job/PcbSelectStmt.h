/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcbSelectStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCB_SELECT_STMT_H
#define PCB_SELECT_STMT_H

#include "PcbCipherTable.h"
#include "PcbDataChunk.h"
#include "PcbStmt.h"

class PcbSelectStmt : public PcbStmt {
   private:
    static const dgt_uint16 PCB_MAX_FETCH_COLS = 1024;

   protected:
    dgt_sint64 TotalRows;
    dgt_uint16 NumFetchCols;
    DgcAttr* FetchColAttrs[PCB_MAX_FETCH_COLS];
    dgt_sint32 NumFetchedRows;

    inline dgt_void addFetchCol(const dgt_schar* col_name, dgt_uint32 max_len) {
        FetchColAttrs[NumFetchCols++] =
            new DgcAttr(DGC_SCHR, max_len, col_name);
    };

   public:
    PcbSelectStmt(PcbCipherTable* cipher_table, dgt_uint32 array_size = 0);
    virtual ~PcbSelectStmt();

    inline dgt_sint64 totalRows() { return TotalRows; };
    inline dgt_uint16 numFetchCols() { return NumFetchCols; };

    inline DgcAttr* fetchColAttr(dgt_uint16 idx) {
        if (idx < NumFetchCols)
            return FetchColAttrs[idx];
        else
            return 0;
    };

    inline dgt_sint32 numFetchedRows() { return NumFetchedRows; };

    virtual dgt_sint32 initialize(dgt_schar* where_clause = 0) throw(
        DgcExcept) = 0;
    virtual dgt_sint32 fetch() throw(DgcExcept) = 0;
    virtual dgt_sint32 fetch(PcbDataChunk* data_chunk) throw(DgcExcept) = 0;
    virtual dgt_sint32 getFetchData(dgt_uint32 col_order, dgt_void** buf,
                                    dgt_sint16** ind,
                                    dgt_uint16** len) throw(DgcExcept) = 0;
};

#endif
