/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcbWorker
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCB_WORKER_H
#define PCB_WORKER_H


#include "DgcWorker.h"
#include "PcbDataChunkPool.h"
#include "PccTableTypes.h"

class PcbWorker : public DgcWorker {
  dgt_uint8	curr_stmt_no;      /* current statement no in CURR_STEP_NO */
  private:
  protected:
	PcbDataChunkPool*	ChunkPool;
	pct_type_worker*		WorkerPtr;

	dgt_void setError(DgcExcept* e);
	virtual dgt_void in() throw(DgcExcept);
	virtual dgt_void out() throw(DgcExcept);
  public:
	static const dgt_sint16	PCB_WKR_STATUS_INITIALIZING=0;
	static const dgt_sint16	PCB_WKR_STATUS_COLLECTING=1;
	static const dgt_sint16	PCB_WKR_STATUS_UPDATING=2;
	static const dgt_sint16	PCB_WKR_STATUS_WAITING=3;
	static const dgt_sint16	PCB_WKR_STATUS_INSERTING=4;
	static const dgt_sint16	PCB_WKR_STATUS_ERROR=10000;
	static const dgt_sint16	PCB_WKR_STATUS_DONE=20000;

	inline pct_type_worker* getWorkerPtr()  {return WorkerPtr;};
        PcbWorker(PcbDataChunkPool* chunk_pool, pct_type_worker* worker_ptr);
        virtual ~PcbWorker();
};


#endif
