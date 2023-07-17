/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcbDataChunk
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCB_DATA_CHUNK_H
#define PCB_DATA_CHUNK_H


#include "DgcObject.h"


class PcbDataColumn : public DgcObject {
  private:
	dgt_uint32	MaxRows;	// the number of maximum rows
	dgt_uint16	MaxColLen;	// the maximum size of column data
	dgt_uint16	MaxEncColLen;	// the maximum size of encrypted column data
	dgt_schar*	ColData;	// the array of column data with the size of "MaxColLen"
	dgt_sint16*	ColInd;		// the array of the null indicator of column data
	dgt_uint16*	ColLen;		// the array of the length of column data
	dgt_schar*	EncColData;	// the array of encrypted column data with the size of "MaxEncColLen"
	dgt_uint16*	EncColLen;	// the array of the length of encrypted column data
	dgt_uint32	NumRows;	// the number of column data added currently
  protected:
  public:
	PcbDataColumn(dgt_uint32 max_rows,dgt_uint16 max_col_len,dgt_uint16 max_enc_col_len=0)
		: MaxRows(max_rows),
		  MaxColLen(max_col_len),
		  MaxEncColLen(max_enc_col_len),
		  ColData(0),
		  ColInd(0),
		  ColLen(0),
		  EncColData(0),
		  EncColLen(0),
		  NumRows(0)
	{
		ColData=new dgt_schar[MaxRows*MaxColLen];
		ColInd=new dgt_sint16[MaxRows];
		ColLen=new dgt_uint16[MaxRows];
		if (max_enc_col_len) {
			EncColData=new dgt_schar[MaxRows*MaxEncColLen];;
			EncColLen=new dgt_uint16[MaxRows];
		}
	};

	virtual ~PcbDataColumn()
	{
		delete ColData;
		delete ColInd;
		delete ColLen;
		delete EncColData;
		delete EncColLen;
	};

	inline dgt_uint16 maxColLen() { return MaxColLen; };
	inline dgt_uint16 maxEncColLen() { return MaxEncColLen; };
	inline dgt_schar* colData(dgt_uint32 row_no=0) { return ColData+row_no*MaxColLen; };
	inline dgt_sint16* colInd(dgt_uint32 row_no=0) { return ColInd+row_no; };
	inline dgt_uint16* colLen(dgt_uint32 row_no=0) { return ColLen+row_no; };
	inline dgt_schar* encColData(dgt_uint32 row_no=0) { if (EncColData) return EncColData+row_no*MaxEncColLen; return 0; };
	inline dgt_uint16* encColLen(dgt_uint32 row_no=0) { if (EncColLen) return EncColLen+row_no; return 0; };
	inline dgt_uint32 numRows() { return NumRows; };

	inline dgt_void reset()
	{
		NumRows = 0;
		if (ColData) memset(ColData,0,MaxColLen*MaxRows);
		if (ColInd) memset(ColInd,0,sizeof(dgt_uint16)*MaxRows);
		if (ColLen) memset(ColLen,0,sizeof(dgt_uint16)*MaxRows);
		if (EncColData) memset(EncColData,0,MaxEncColLen*MaxRows);
		if (EncColLen) memset(EncColLen,0,sizeof(dgt_uint16)*MaxRows);
	};

	inline dgt_uint32 putData(const dgt_uint32 num_rows,dgt_schar* col_data,dgt_sint16* col_ind,dgt_uint16* col_len)
	{
		if (num_rows > MaxRows) return 0;
		if (num_rows > 0) {
			memcpy(ColData, col_data, num_rows*MaxColLen);
			memcpy(ColInd, col_ind, num_rows*sizeof(dgt_sint16));
			memcpy(ColLen, col_len, num_rows*sizeof(dgt_uint16));
		}
		return NumRows=num_rows;
	};

	inline dgt_uint32 putData(const dgt_schar* col_data, dgt_sint16 col_ind, dgt_uint16 col_len)
	{
		if (NumRows >= MaxRows) return 0;
		if (col_len >= MaxColLen) col_len = MaxColLen - 1;
		if (col_len != 0) strncpy(ColData + NumRows*MaxColLen, col_data, col_len);
		ColInd[NumRows] = col_ind;
		ColLen[NumRows] = col_len;
		return NumRows++;
	};

	inline dgt_uint32 putEncData(const dgt_uint32 num_rows,dgt_schar* col_data,dgt_sint16* col_ind,dgt_uint16* col_len)
	{
		if (num_rows > MaxRows) return 0;
		if (num_rows > 0 && EncColData) {
			memcpy(EncColData, col_data, num_rows*MaxEncColLen);
			memcpy(ColInd, col_ind, num_rows*sizeof(dgt_sint16));
			memcpy(EncColLen, col_len, num_rows*sizeof(dgt_uint16));
		}
		return NumRows=num_rows;
	};

	inline dgt_uint32 putEncData(const dgt_schar* col_data, dgt_sint16 col_ind, dgt_uint16 col_len)
	{
		if (NumRows >= MaxRows) return 0;
		if (col_len >= MaxEncColLen) col_len = MaxEncColLen - 1;
		if (col_len != 0) strncpy(EncColData + NumRows*MaxEncColLen, col_data, col_len);
		ColInd[NumRows] = col_ind;
		EncColLen[NumRows] = col_len;
		return NumRows++;
	};
};


#include "DgcSpinLock.h"
#include "DgcExcept.h"

class PcbDataChunk : public DgcObject {
  private:
	dgt_uint16	ChunkID;	// chunk ID, which is the descriptor of the chunk array in the ChunkPool
	dgt_uint32	MaxRows;	// the maximum number of rows in a chunk
	dgt_uint16	NumColumns;	// the number of columns in a chunk
	dgt_uint16	NumIdxColumns;	// the number of Index columns in a chunk
	dgt_uint16	AddColumns;	// the number of columns currently added
	PcbDataColumn**	DataColumns;	// the array of pointer to DataColumn
	dgt_slock	Latch;		// spin lock
	dgt_uint8	Stat;		// chunk status
  protected:
  public:
	static const dgt_uint8	PCB_CHUNK_STAT_NULL	=0;
	static const dgt_uint8	PCB_CHUNK_STAT_EMPTY	=1;
	static const dgt_uint8	PCB_CHUNK_STAT_LOADING	=2;	// after a collector gets it
	static const dgt_uint8	PCB_CHUNK_STAT_LOADED	=3;	// after the collector returns it
	static const dgt_uint8	PCB_CHUNK_STAT_UPDATING	=4;	// after updater gets it

	PcbDataChunk(dgt_uint16 chunk_id,dgt_uint32 max_rows,dgt_uint16 num_columns,dgt_uint16 num_idxcolumns=0);
	virtual ~PcbDataChunk();

	inline dgt_uint16 chunkID() { return ChunkID; };
	inline dgt_uint32 numRows() { return DataColumns[0]->numRows(); };
	inline dgt_uint16 numColumns() { return NumColumns; };
	inline dgt_uint16 numIdxColumns() { return NumIdxColumns; };
	inline dgt_uint8 stat() { return Stat; };
	inline PcbDataColumn* dataColumn(dgt_uint32 col_no) { if (col_no < NumColumns+NumIdxColumns) return DataColumns[col_no]; return 0; };
	inline dgt_void reset() { for(dgt_uint16 i=0; i<NumColumns; i++) DataColumns[i]->reset(); };

	inline PcbDataChunk* setStat(dgt_uint8 set_stat,dgt_uint8 test_stat=PCB_CHUNK_STAT_NULL)
	{
		PcbDataChunk*	data_chunk=0;
		if (test_stat == PCB_CHUNK_STAT_NULL) {
			Stat=set_stat;
			data_chunk=this;
		} else {
			if (DgcSpinLock::lock(&Latch)) {
				delete EXCEPTnC;
			} else { // locked & test & set
				if (Stat == test_stat) {
					Stat=set_stat;
					data_chunk=this;
				}
				DgcSpinLock::unlock(&Latch);
			}
		}
		return data_chunk;
	};

	dgt_uint16 addColumn(dgt_uint16 max_col_len,dgt_uint16 max_enc_col_len=0);
	dgt_uint16 addIdxColumn(dgt_uint16 max_col_len,dgt_uint16 max_enc_col_len=0);
};


#endif
