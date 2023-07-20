/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PcbWorker
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcbWorker.h"

PcbWorker::PcbWorker(PcbDataChunkPool* chunk_pool, pct_type_worker* worker_ptr)
    : ChunkPool(chunk_pool), WorkerPtr(worker_ptr) {}

PcbWorker::~PcbWorker() {}

dgt_void PcbWorker::setError(DgcExcept* e) {
    DgcError* err = e->getErr();
    while (err->next()) err = err->next();
    strncpy(WorkerPtr->err_msg, err->message(), 128);
    WorkerPtr->curr_status = PCB_WKR_STATUS_ERROR;
}

dgt_void PcbWorker::in() throw(DgcExcept) {
    WorkerPtr->thread_id = this->tid();
    WorkerPtr->start_time = dgtime(&WorkerPtr->start_time);
}

dgt_void PcbWorker::out() throw(DgcExcept) {
    WorkerPtr->end_time = dgtime(&WorkerPtr->end_time);
}
