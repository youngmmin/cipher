#ifndef PCC_FREE_CRYPT_BUF_LIST_H
#define PCC_FREE_CRYPT_BUF_LIST_H

#include "DgcSpinLock.h"
#include "PccWaiter.h"
#include "PccCryptBuffer.h"

class PccFreeCryptBufList : public DgcObject {
  private:
protected:
	PccWaiters	Waiters;
	dgt_uint64	SeqNo;		// buffer sequence number
	dgt_uint8*	SrcDatas;	// source data area
	dgt_uint8*	DstDatas;	// destination data area
	PccCryptBuffer*	CryptBuffers;	// crypt buffer array
	PccCryptBuffer*	FirstFree;	// the first of free list
	PccCryptBuffer*	LastFree;	// the last of free list
	dgt_sint32	NumBuffers;	// # of buffers
	dgt_sint32	SrcBufLen;	// the length of source buffer
	dgt_sint32	DstBufLen;	// the length of destination buffer
	dgt_sint32	CryptMode;	// crypt mode, encrypt = 1, decrypt = 0
	dgt_slock	ListLock;	// concurrency control spin lock
  public:
	PccFreeCryptBufList(dgt_sint32 crypt_mode,dgt_sint32 num_buffers,dgt_sint32 src_buf_len);
	virtual ~PccFreeCryptBufList() { delete[] CryptBuffers; delete DstDatas; delete SrcDatas; }

	inline dgt_uint8 isCreate() { return CryptBuffers?1:0; };
	inline dgt_uint64 seqNo() { return SeqNo; };

	PccCryptBuffer* get(PccWaiter* waiter=0)
	{
		PccCryptBuffer* rtn = 0;
		if (DgcSpinLock::lock(&ListLock) == 0) {
			if ((rtn=FirstFree)) {
				if ((FirstFree=rtn->Next) == 0) FirstFree = LastFree = 0; // now empty
				rtn->readReset(SeqNo++,SrcBufLen,DstBufLen);
			}
			if (rtn == 0) Waiters.enroll(waiter);
			DgcSpinLock::unlock(&ListLock);
			if (rtn == 0 && waiter) waiter->waiting();
		}
		return rtn;
	}

	dgt_void put(PccCryptBuffer* crypt_buf)
	{
		if (crypt_buf) {
			crypt_buf->Next = 0;
			for(;;) { // until holding the list lock
				if (DgcSpinLock::lock(&ListLock) == 0) {
					if (LastFree) LastFree->Next = crypt_buf;
					else FirstFree = crypt_buf;
					LastFree = crypt_buf;
					while(LastFree->Next) LastFree = LastFree->Next;
					if (Waiters.numWaiters()) Waiters.wakeup();
					DgcSpinLock::unlock(&ListLock);
					break;
				}
			}
		}
	}
};


class PccCryptBufFifoQueue {
  private:
	PccWaiters	Waiters;
	PccCryptBuffer*	First;		// queue header
	PccCryptBuffer*	Last;		// queue tail
	dgt_sint32	Size;		// current queue size
	dgt_uint64	TotalBuffers;	// the total buffers to be passed
	dgt_uint64	MissCount;	// spin lock miss counter
	dgt_uint64	InCount;	// # buffer coming in
	dgt_uint64	OutCount;	// # buffer going out
	dgt_slock	QueueLock;	// spin lock
  protected:
  public:
	PccCryptBufFifoQueue()
		: First(0), Last(0), Size(0), TotalBuffers(0), MissCount(0), InCount(0), OutCount(0)
	{ 
		DgcSpinLock::unlock(&QueueLock);
	}
	~PccCryptBufFifoQueue() {}

	dgt_sint32 size() { return Size; }
	dgt_uint64 missCount() { return MissCount; }
	dgt_uint64 inCount() { return InCount; }
	dgt_uint64 outCount() { return OutCount; }

	dgt_void setTotalBuffers(dgt_uint64 total_buffers) { TotalBuffers = total_buffers; Waiters.wakeup(); }

	dgt_void put(PccCryptBuffer* crypt_buf) 
	{
		if (crypt_buf) {
			for(;;) { // until holding the queue lock
				if (DgcSpinLock::lock(&QueueLock) == 0) {
					if (Last) Last->Next = crypt_buf;
					else First = crypt_buf;
					Last = crypt_buf;
					Size++;
					InCount++;
					while(Last->Next) {
						Size++;
						InCount++;
						Last = Last->Next;
					}
					if (Waiters.numWaiters()) Waiters.wakeup();
					DgcSpinLock::unlock(&QueueLock);
					break;
				} else {
					MissCount++;
				}
			}
		}
	}

	//
	// return value: 1 => buffer fetched, 0 -> empty, -1 => end of job
	//
	dgt_sint32 get(PccCryptBuffer** rtn,PccWaiter* waiter=0)
	{
		*rtn = 0;
		if (DgcSpinLock::lock(&QueueLock) == 0) {
			if ((*rtn=First)) {
				Size--;
				OutCount++;
				First = First->Next;
			}
			if (First == 0) Last = 0;
			if (*rtn == 0) Waiters.enroll(waiter);
			DgcSpinLock::unlock(&QueueLock);
			if (*rtn) {(*rtn)->Next = 0; return 1; }
			if (TotalBuffers && (Size == 0 || OutCount)) return -1; // the end of job to do
			if (waiter) waiter->waiting();
		} else MissCount++;
		return 0; // empty
	}
};


class PccCryptBufSortQueue : public DgcObject {
  private:
	dgt_uint64		Sequence;	// the next crypted buffer sequence number
	PccCryptBuffer**	BufferPtrs;	// sort buffer circular queue buffers
	dgt_sint32		NumBuffers;	// the size of queue
	dgt_sint32		HeaderIdx;	// queue header index 
	dgt_sint32		Size;		// queue size
	dgt_uint64		MissCount;	// spin lock miss count
	dgt_uint64		InCount;	// # buffer coming in
	dgt_uint64		OutCount;	// # buffer going out
	dgt_slock		QueueLock;	// spin lock
  protected:
  public:
	PccCryptBufSortQueue(dgt_sint32 num_buffers)
		: Sequence(0), BufferPtrs(0), NumBuffers(num_buffers), HeaderIdx(0), Size(0), MissCount(0), InCount(0), OutCount(0)
	{
		BufferPtrs = new PccCryptBuffer*[NumBuffers];
		for(dgt_sint32 i=0; i<NumBuffers; i++) *(BufferPtrs+i) = 0;
		DgcSpinLock::unlock(&QueueLock);
	}
	virtual ~PccCryptBufSortQueue() { delete BufferPtrs; }

	dgt_sint32 size() { return Size; };
	dgt_uint64 missCount() { return MissCount; }
	dgt_uint64 inCount() { return InCount; }
	dgt_uint64 outCount() { return OutCount; }

	PccCryptBuffer* put(PccCryptBuffer* crypt_buf) // return a crypted buffer list if the crypt_buf is the next crypted buffer
	{
		PccCryptBuffer* rtn = 0;
		if (crypt_buf) {
			for(;;) { // until holding the queue lock
				if (DgcSpinLock::lock(&QueueLock) == 0) {
					*(BufferPtrs+((HeaderIdx + crypt_buf->SeqNo - Sequence) % NumBuffers)) = crypt_buf; // put in the queue
					Size++;
					InCount++;
					// cut and return a sorted list
					if ((rtn=*(BufferPtrs+HeaderIdx))) {
						PccCryptBuffer* last;
						do {
							last = *(BufferPtrs+HeaderIdx);
							*(BufferPtrs+HeaderIdx) = 0;
							Size--;
							OutCount++;
							HeaderIdx = (HeaderIdx + 1) % NumBuffers; // move the HeaderIdx to the next slot
							Sequence++;
						} while ((last->Next=*(BufferPtrs+HeaderIdx)));
					}
					DgcSpinLock::unlock(&QueueLock);
					break;
				} else {
					MissCount++;
				}
			}
		}
		return rtn;
	}
};


class PccCryptList {
  private:
	PccCryptBufSortQueue	SortQueue;
	PccCryptBufFifoQueue	WriteQueue;
	dgt_slock		ListLock;	// spin lock
  protected:
  public:
	PccCryptList(dgt_sint32 num_buffers) : SortQueue(num_buffers) { DgcSpinLock::unlock(&ListLock); }
	virtual ~PccCryptList() {}
	PccCryptBufFifoQueue& writeQueue() { return WriteQueue; };
	dgt_void setTotalBuffers(dgt_uint64 total_buffers) { WriteQueue.setTotalBuffers(total_buffers); }
	dgt_sint32 sortQueueSize() { return SortQueue.size(); }
	dgt_uint64 missCount() { return SortQueue.missCount() + WriteQueue.missCount(); }
	dgt_uint64 sortInCount() { return SortQueue.inCount(); }
	dgt_uint64 sortOutCount() { return SortQueue.outCount(); }
	dgt_uint64 writeInCount() { return WriteQueue.inCount(); }
	dgt_uint64 writeOutCount() { return WriteQueue.outCount(); }
	dgt_void put(PccCryptBuffer* crypt_buf)
	{
		for(;;) { // until holding the queue lock
			if (DgcSpinLock::lock(&ListLock) == 0) {
				if ((crypt_buf=SortQueue.put(crypt_buf))) WriteQueue.put(crypt_buf);
				DgcSpinLock::unlock(&ListLock);
				break;
			}
		}
	}
	dgt_sint32 get(PccCryptBuffer** rtn,PccWaiter* waiter=0) { return WriteQueue.get(rtn,waiter); }
};


#endif
