#ifndef PCC_CIPHER_H
#define PCC_CIPHER_H

#include "PccCryptorFactory.h"
#include "PccFileCipherConstTypes.h"
#include "PccFreeCryptBufList.h"

class PccCipher : public DgcWorker {
   private:
    PccWaiterNap Waiter;
    PccCryptBufFifoQueue& DataQueue;
    PccCryptList& CryptQueue;
    PccPttnSearchEngine* SearchEngine;
    PccCryptor* Cryptor;
    dgt_sint32* LastErrCode;
    dgt_uint32 DataQueueWaits;
    dgt_uint32 CryptBuffers;
    dgt_sint64 OutBufLen;

   protected:
    virtual dgt_sint32 run() throw(DgcExcept);

   public:
    PccCipher(PccCryptBufFifoQueue& dq, PccCryptList& cq,
              PccPttnSearchEngine* pse, PccCryptor* cryptor,
              dgt_sint32* last_err_code)
        : DataQueue(dq),
          CryptQueue(cq),
          SearchEngine(pse),
          Cryptor(cryptor),
          LastErrCode(last_err_code),
          DataQueueWaits(0),
          CryptBuffers(0),
          OutBufLen(0) {}
    virtual ~PccCipher() {}

    dgt_sint64 outBufLen() { return OutBufLen; }

    dgt_sint32 crypt(PccCryptBuffer* curr) {
        dgt_sint32 rtn = 0;
        rtn = SearchEngine->patternSearch(
            curr);  // search patterns in the data buffer
        if (rtn < 0) {
            *LastErrCode = rtn;
            return rtn;
        }
        rtn = Cryptor->crypt(curr);
        if (rtn < 0) {
            *LastErrCode = rtn;
            return rtn;
        }
        CryptBuffers++;
#if 1  // added by mwpark for encrypt bytes logging
        OutBufLen += rtn;
#else
        if (OutBufLen == 0) OutBufLen = rtn;
#endif
        return rtn;
    }
};

#endif
