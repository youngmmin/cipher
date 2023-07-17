/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PcbCollector
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcbCollector.h"

PcbCollector::PcbCollector(PcbSelectStmt* select_stmt,PcbDataChunkPool* chunk_pool,pct_type_worker* worker_ptr)
	: PcbWorker(chunk_pool,worker_ptr),
	  SelectStmt(select_stmt)
{
	strncpy(WorkerPtr->assigned_role,"collector",10);
}


PcbCollector::~PcbCollector()
{
	delete SelectStmt;
}


dgt_sint32 PcbCollector::run() throw(DgcExcept)
{
	dgt_sint32	rtn;
	PcbDataChunk*	data_chunk;
	while((data_chunk=ChunkPool->getEmptyChunk()) && WorkerPtr->curr_status != PCB_WKR_STATUS_ERROR) {
		WorkerPtr->curr_status = PCB_WKR_STATUS_COLLECTING;
		struct timeval stime;
		gettimeofday(&stime,0);

		if ((rtn=SelectStmt->fetch(data_chunk)) < 0) {
			DgcExcept*	e=EXCEPTnC;
			setError(e);
			//ATHROWnR(DgcError(SPOS,"fetch failed"),rtn);
			RTHROWnR(e,DgcError(SPOS,"fetch failed."),rtn);
		} else if (rtn == 0) {
			ChunkPool->finishCollecting(data_chunk);
			WorkerPtr->curr_status = PCB_WKR_STATUS_DONE;
			return 1;
		} else {
			ChunkPool->putLoadedChunk(data_chunk);

			WorkerPtr->processed_chunks++;
			WorkerPtr->processed_rows+=rtn;

			struct timeval etime;
			gettimeofday(&etime,0);
			if (etime.tv_sec == stime.tv_sec) WorkerPtr->working_time += etime.tv_usec - stime.tv_usec;
			else WorkerPtr->working_time += (dgt_sint64)(etime.tv_sec - stime.tv_sec)*1000000 + etime.tv_usec - stime.tv_usec;
		}
	}

	WorkerPtr->curr_status = PCB_WKR_STATUS_WAITING;
	WorkerPtr->chunk_waits++;
	napAtick();
	return 0;
}
