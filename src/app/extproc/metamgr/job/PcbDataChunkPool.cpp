/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PcbDataChunkPool
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcbDataChunkPool.h"
#include "PciCryptoIf.h"


PcbDataChunkPool::PcbDataChunkPool(dgt_uint16 num_chunks)
	: NumChunks(num_chunks),
	  IsFinishCollecting(0)
{
	if (NumChunks == 0) NumChunks=PCB_DFLT_CHUNKS;
	for(dgt_uint16 i=0; i<PCB_MAX_CHUNKS; i++) ChunkPool[i]=0;
}


PcbDataChunkPool::~PcbDataChunkPool()
{
	for(dgt_uint16 i=0; i<NumChunks; i++) delete ChunkPool[i];
}


dgt_void PcbDataChunkPool::initialize(PcbCipherTable* cipher_table,PcbSelectStmt* select_stmt)
{
	for(dgt_uint16 cid=0; cid<NumChunks; cid++) {
		PcbDataChunk*	data_chunk=new PcbDataChunk(cid, select_stmt->arraySize(), select_stmt->numFetchCols(),cipher_table->numIndexes());
		for(dgt_uint16 cno=0; cno<select_stmt->numFetchCols(); cno++) {
			DgcAttr*	attr=select_stmt->fetchColAttr(cno);
			if ((cno+1) == select_stmt->numFetchCols()){
				if(cipher_table->getDecryptFlag()==PCB_DECRYPT_FLAG_ENCRYPT){
					for(dgt_uint16 idxno=0; idxno<cipher_table->numIndexes(); idxno++ ) {
						data_chunk->addIdxColumn(attr->length(), 2000); //the index column, raw(2000)
					}
				}
				data_chunk->addColumn(attr->length()); // the last column, rowid
			}
			else if (cipher_table->getDecryptFlag()==PCB_DECRYPT_FLAG_DECRYPT
					||cipher_table->getDecryptFlag()==PCB_DECRYPT_FLAG_VERIFICATION) data_chunk->addColumn(attr->length(), attr->length());
			else data_chunk->addColumn(attr->length(), attr->length()+16+16+4+PCI_ophuekLength(attr->length(),PCI_SRC_TYPE_CHAR,1));
		}
		ChunkPool[cid]=data_chunk;
	}
}
