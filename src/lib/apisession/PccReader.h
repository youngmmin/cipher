#ifndef PCC_READER_H
#define PCC_READER_H

#ifndef WIN32
#include "DgcNamedPipeStream.h"
#include "PciMsgTypes.h"
#endif
#include "PccFileCipherConstTypes.h"
#include "PccFreeCryptBufList.h"
#include "PccSearchEngineFactory.h"

class PccReader : public DgcWorker {
   private:
    PccWaiterNap Waiter;
    DgcFileStream* InStream;
    PccFreeCryptBufList& CryptBufList;
    PccPttnSearchEngine* SearchEngine;
    PccCryptBufFifoQueue& DataQueue;
    dgt_uint16 HeaderSize;
    dgt_sint32* LastErrCode;
    PccCryptBuffer* CurrBuf;
    PccCryptBuffer* NextBuf;
    dgt_uint32 FreeListWaits;
    dgt_uint32 ReadBuffers;
    dgt_sint64 RemainBytes;
    dgt_sint32 StreamFlag;
    dgt_sint32 StopFlag;

    virtual dgt_void in() throw(DgcExcept);
    virtual dgt_sint32 run() throw(DgcExcept);

   protected:
   public:
    PccReader(DgcFileStream* in_stream, PccFreeCryptBufList& cbl,
              PccPttnSearchEngine* pse, PccCryptBufFifoQueue& dq,
              dgt_uint16 header_size, dgt_sint32* last_err_code,
              dgt_sint32 stream_flag = 0)
        : InStream(in_stream),
          CryptBufList(cbl),
          SearchEngine(pse),
          DataQueue(dq),
          HeaderSize(header_size),
          LastErrCode(last_err_code),
          CurrBuf(0),
          NextBuf(0),
          FreeListWaits(0),
          ReadBuffers(0),
          RemainBytes(0),
          StreamFlag(stream_flag),
          StopFlag(0) {
        RemainBytes = InStream->fileSize();
    };
    virtual ~PccReader() {}

    dgt_void askStop() { StopFlag = 1; };
    inline void setRemainBytes(dgt_sint64 remain_bytes) {
        RemainBytes = remain_bytes;
    };
    inline dgt_uint32 freeListWaits() { return FreeListWaits; };
    inline dgt_uint32 readBuffers() { return ReadBuffers; };
    dgt_sint32 readAndHandover(PccCryptBuffer** rtn_buf) throw(DgcExcept);
};

#endif
