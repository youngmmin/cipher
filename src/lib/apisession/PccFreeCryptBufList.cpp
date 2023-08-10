
#include "PccFreeCryptBufList.h"

#include "DgcWorker.h"  //for logging.. this class is no thread

PccFreeCryptBufList::PccFreeCryptBufList(dgt_sint32 crypt_mode,
                                         dgt_sint32 num_buffers,
                                         dgt_sint32 src_buf_len)
    : SeqNo(0),
      SrcDatas(0),
      DstDatas(0),
      CryptBuffers(0),
      FirstFree(0),
      LastFree(0),
      NumBuffers(num_buffers),
      SrcBufLen(src_buf_len),
      DstBufLen(0),
      CryptMode(crypt_mode) {
    // create the array of source buffers
    // one more byte for null terminating that is necessary for pattern search
    if ((SrcDatas = new dgt_uint8[(SrcBufLen + 1) * NumBuffers]) == 0) {
        DgcWorker::PLOG.tprintf(
            0, "fail to get memory[(%d)*%d] for text buffer datas.\n",
            SrcBufLen, NumBuffers);
        return;
    }
    // create the array of destination buffers
    if (CryptMode == PFC_CRYPT_MODE_ENCRYPT)
        DstBufLen = SrcBufLen * 3 * 1.4;  // in case of encrypting the length of
                                          // output is bigger than input
    else if (CryptMode == PFC_CRYPT_MODE_DECRYPT ||
             CryptMode == PFC_CRYPT_MODE_MIGRATION ||
             CryptMode == PFC_CRYPT_MODE_BACKUP)
        DstBufLen = SrcBufLen;
    else {
        DgcWorker::PLOG.tprintf(0, "unknown CryptMode [%d]\n", CryptMode);
        return;
    }

    if ((DstDatas = new dgt_uint8[DstBufLen * NumBuffers]) == 0) {
        DgcWorker::PLOG.tprintf(
            0, "fail to get memory[%d*%d] for text buffer datas.\n", DstBufLen,
            NumBuffers);
        return;
    }
    // create the array of crypt buffers
    if ((CryptBuffers = new PccCryptBuffer[NumBuffers]) == 0) {
        DgcWorker::PLOG.tprintf(0,
                                "fail to get memory[%d*%d] for text buffers.\n",
                                sizeof(PccCryptBuffer), NumBuffers);
        return;
    }
    // initializing the free buffer list
    PccCryptBuffer* curr = 0;
    for (dgt_sint32 i = 0; i < NumBuffers - 1; i++) {
        curr = CryptBuffers + i;
        curr->Next = curr + 1;
        curr->SrcDataPtr = SrcDatas + (i * (SrcBufLen + 1));
        curr->DstDataPtr = DstDatas + (i * DstBufLen);
    }
    curr = CryptBuffers + NumBuffers - 1;  // for the last buffer
    curr->Next = 0;
    curr->SrcDataPtr = SrcDatas + ((NumBuffers - 1) * (SrcBufLen + 1));
    curr->DstDataPtr = DstDatas + ((NumBuffers - 1) * DstBufLen);
    FirstFree = CryptBuffers;
    LastFree = CryptBuffers + NumBuffers - 1;
    DgcSpinLock::unlock(&ListLock);
}
