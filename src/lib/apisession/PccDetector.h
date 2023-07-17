#ifndef PCC_DETECTOR_H
#define PCC_DETECTOR_H

#include "PccFileCipherConstTypes.h"
#include "PccFreeCryptBufList.h"
#include "PccCryptorFactory.h"

class PccDetector : public DgcWorker {
  private:
	PccWaiterNap		Waiter;
	PccCryptBufFifoQueue&	DataQueue;
	PccCryptList&		CryptQueue;
	PccPttnSearchEngine*	SearchEngine;
	dgt_sint32*		LastErrCode;
	dgt_uint32		DataQueueWaits;
	dgt_uint32		CryptBuffers;
	dgt_sint64		NumPttns;
	dgt_sint32		StopFlag;
  protected:
	virtual dgt_sint32 run() throw(DgcExcept);
  public:
	PccDetector(PccCryptBufFifoQueue& dq,PccCryptList& cq,PccPttnSearchEngine* pse,dgt_sint32* last_err_code)
  	  : DataQueue(dq),CryptQueue(cq),SearchEngine(pse),LastErrCode(last_err_code),DataQueueWaits(0),CryptBuffers(0),NumPttns(0),StopFlag(0) {}
	virtual ~PccDetector() {}

	dgt_sint64 numPttns() { return NumPttns; }
	dgt_void askStop() { StopFlag = 1; }

	dgt_sint32 detect(PccCryptBuffer *curr)
	{
		if (StopFlag) return 0; 
		dgt_sint32 rtn = 0;
		rtn = SearchEngine->patternSearch(curr); // search patterns in the data buffer
		if (rtn < 0) {
			*LastErrCode = rtn;
			return rtn;
		}
		NumPttns += rtn;

		unsigned char* cdbp = curr->DstDataPtr;	// the current detecting buffer pointer
		PccSegment* seg;
		dgt_uint32 dst_buf_len = curr->DstLength;
		curr->DstLength = 0;
		curr->SegList->rewind();

		while((seg=curr->SegList->next())) {
			unsigned char* sp = curr->SrcDataPtr + seg->sOffset();
			if (seg->type() == PccSegment::SEG_T_PTTN) { // pattern segment => should be saved
				pc_type_detect_file_data_in buf;
				memset(&buf, 0, sizeof(pc_type_detect_file_data_in));
				buf.start_offset = curr->FirstSplitPttnOffset + seg->sOffset();
				buf.end_offset = curr->FirstSplitPttnOffset + seg->eOffset();
				memcpy(buf.expr, seg->expr(), strlen(seg->expr()));
				memcpy(buf.data, sp, seg->length());

				memcpy(cdbp, &buf, sizeof(buf));
				cdbp += sizeof(buf);
				curr->DstLength += sizeof(buf);
			} 
		}
		CryptBuffers++;

		return rtn;
	}
};


#endif
