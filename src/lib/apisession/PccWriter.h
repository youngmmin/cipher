#ifndef PCC_WRITER_H
#define PCC_WRITER_H

#include "DgcFileStream.h"
#include "DgcWorker.h"
#include "PccFreeCryptBufList.h"

class PccWriter : public DgcWorker {
   private:
    PccWaiterNap Waiter;
    DgcFileStream* OutStream;
    PccCryptList& CryptQueue;
    PccFreeCryptBufList& CryptBufList;
    dgt_sint32* LastErrCode;
    dgt_uint32 CryptQueueWaits;
    dgt_uint32 WriteBuffers;
    dgt_sint32 StreamFlag;
    dgt_sint32 StopFlag;
    dgt_sint64 OrgSize;

    virtual dgt_sint32 run() throw(DgcExcept);

   protected:
   public:
    PccWriter(DgcFileStream* out_stream, PccCryptList& cq,
              PccFreeCryptBufList& cbl, dgt_sint32* last_err_code,
              dgt_sint32 stream_flag = 0)
        : OutStream(out_stream),
          CryptQueue(cq),
          CryptBufList(cbl),
          LastErrCode(last_err_code),
          CryptQueueWaits(0),
          WriteBuffers(0),
          StreamFlag(stream_flag),
          StopFlag(0),
          OrgSize(0) {}
    virtual ~PccWriter() {}

    dgt_void askStop() { StopFlag = 1; }
    dgt_void setOrgSize(dgt_sint64 org_size) { OrgSize = org_size; }
    dgt_uint32 cryptQueueWaits() { return CryptQueueWaits; }
    dgt_uint32 writeBuffers() { return WriteBuffers; }
    dgt_sint32 write(PccCryptBuffer* curr) throw(DgcExcept);
};

#endif
