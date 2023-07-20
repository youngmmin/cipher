/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PcbDataChunk
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcbDataChunk.h"

PcbDataChunk::PcbDataChunk(dgt_uint16 chunk_id, dgt_uint32 max_rows,
                           dgt_uint16 num_columns, dgt_uint16 num_idxcolumns)
    : ChunkID(chunk_id),
      MaxRows(max_rows),
      NumColumns(num_columns),
      NumIdxColumns(num_idxcolumns),
      AddColumns(0),
      DataColumns(0),
      Stat(PCB_CHUNK_STAT_EMPTY) {
    DataColumns = new PcbDataColumn*[NumColumns + NumIdxColumns];
    for (dgt_uint16 i = 0; i < NumColumns + NumIdxColumns; i++)
        DataColumns[i] = 0;
    DgcSpinLock::unlock(&Latch);
}

PcbDataChunk::~PcbDataChunk() {
    for (dgt_uint16 i = 0; i < NumColumns; i++) delete DataColumns[i];
    delete DataColumns;
}

dgt_uint16 PcbDataChunk::addColumn(dgt_uint16 max_col_len,
                                   dgt_uint16 max_enc_col_len) {
    if (AddColumns < NumColumns + NumIdxColumns) {
        DataColumns[AddColumns++] =
            new PcbDataColumn(MaxRows, max_col_len, max_enc_col_len);
        return AddColumns;
    }
    return 0;
}

dgt_uint16 PcbDataChunk::addIdxColumn(dgt_uint16 max_col_len,
                                      dgt_uint16 max_enc_col_len) {
    if (AddColumns < NumColumns + NumIdxColumns) {
        DataColumns[AddColumns++] =
            new PcbDataColumn(MaxRows, max_col_len, max_enc_col_len);
        return AddColumns;
    }
    return 0;
}
