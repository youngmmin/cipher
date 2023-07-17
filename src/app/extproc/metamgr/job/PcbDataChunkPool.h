/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcbDataChunkPool
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCB_DATA_CHUNK_POOL_H
#define PCB_DATA_CHUNK_POOL_H


#include "PcbSelectStmt.h"


class PcbDataChunkPool : public DgcObject {
  private:
	static const dgt_uint16	PCB_MAX_CHUNKS=5000;
	static const dgt_uint16	PCB_DFLT_CHUNKS=10;

	dgt_uint16	NumChunks;
	PcbDataChunk*	ChunkPool[PCB_MAX_CHUNKS];
	dgt_uint8	IsFinishCollecting;
  protected:
  public:
        PcbDataChunkPool(dgt_uint16 num_chunks=0);
        virtual ~PcbDataChunkPool();

	inline dgt_uint8 isFinishCollecting() { return IsFinishCollecting; };

	inline PcbDataChunk* getEmptyChunk()
	{
		PcbDataChunk*	data_chunk=0;
		for(dgt_uint16 cid=0; cid<NumChunks; cid++) {
			if (ChunkPool[cid]->stat() == PcbDataChunk::PCB_CHUNK_STAT_EMPTY) {
				if ((data_chunk=ChunkPool[cid]->setStat(PcbDataChunk::PCB_CHUNK_STAT_LOADING,PcbDataChunk::PCB_CHUNK_STAT_EMPTY)))
					break;
			}
		}
		return data_chunk;
	};

	inline dgt_void putLoadedChunk(PcbDataChunk* data_chunk)
	{
		data_chunk->setStat(PcbDataChunk::PCB_CHUNK_STAT_LOADED);
	};

	inline PcbDataChunk* getLoadedChunk()
	{
		PcbDataChunk*	data_chunk=0;
		for(dgt_uint16 cid=0; cid<NumChunks; cid++) {
			if (ChunkPool[cid]->stat() == PcbDataChunk::PCB_CHUNK_STAT_LOADED) {
				if ((data_chunk=ChunkPool[cid]->setStat(PcbDataChunk::PCB_CHUNK_STAT_UPDATING,PcbDataChunk::PCB_CHUNK_STAT_LOADED)))
					break;
			}
		}
		return data_chunk;
	};

	inline dgt_void putEmptyChunk(PcbDataChunk* data_chunk)
	{
		data_chunk->setStat(PcbDataChunk::PCB_CHUNK_STAT_EMPTY);
	};

	inline dgt_void finishCollecting(PcbDataChunk* data_chunk)
	{
		data_chunk->setStat(PcbDataChunk::PCB_CHUNK_STAT_EMPTY);
		IsFinishCollecting=1;
	};

	dgt_void initialize(PcbCipherTable* cipher_table,PcbSelectStmt* select_stmt);
};


#endif
