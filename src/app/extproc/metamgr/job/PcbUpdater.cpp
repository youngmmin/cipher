/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PcbUpdater
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcbUpdater.h"


PcbUpdater::PcbUpdater(PcbUpdateStmt* update_stmt,PcbDataChunkPool* chunk_pool,pct_type_worker* worker_ptr)
	: PcbWorker(chunk_pool,worker_ptr),
	  UpdateStmt(update_stmt)
{
	strncpy(WorkerPtr->assigned_role,"updater",10);
}


PcbUpdater::~PcbUpdater()
{
	delete UpdateStmt;
}


dgt_sint32 PcbUpdater::run() throw(DgcExcept)
{
	dgt_sint32	rtn;
	PcbDataChunk*	data_chunk;
	while((data_chunk=ChunkPool->getLoadedChunk())) {

		WorkerPtr->curr_status = PCB_WKR_STATUS_UPDATING;
		struct timeval stime;
		gettimeofday(&stime,0);

		if ((rtn=UpdateStmt->update(data_chunk)) < 0) {
			DgcExcept*	e=EXCEPTnC;
			ChunkPool->putLoadedChunk(data_chunk);
			setError(e);
            RTHROWnR(e,DgcError(SPOS,"update failed"),rtn);
		}
		WorkerPtr->processed_chunks++;
		WorkerPtr->processed_rows+=data_chunk->numRows();
		ChunkPool->putEmptyChunk(data_chunk);

		struct timeval etime;
		gettimeofday(&etime,0);
		if (etime.tv_sec == stime.tv_sec) WorkerPtr->working_time += etime.tv_usec - stime.tv_usec;
		else WorkerPtr->working_time += (dgt_sint64)(etime.tv_sec-stime.tv_sec)*1000000 + etime.tv_usec - stime.tv_usec;
        }
	if (ChunkPool->isFinishCollecting()) {
		WorkerPtr->curr_status = PCB_WKR_STATUS_DONE;
		return 1;
	}

	WorkerPtr->curr_status = PCB_WKR_STATUS_WAITING;
	WorkerPtr->chunk_waits++;
	napAtick();
        return 0;
}
