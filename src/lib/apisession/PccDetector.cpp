#include "PccDetector.h"

dgt_sint32 PccDetector::run() throw(DgcExcept) {
    PccCryptBuffer* curr = 0;
    dgt_sint32 rtn;
    if (*LastErrCode) return 1;
    while ((rtn = DataQueue.get(&curr, &Waiter)) == 0) {
        if (StopFlag) return 1;
        if (*LastErrCode) return 1;  // added by ihjin for thread normal stop
        DataQueueWaits++;
    }
    if (rtn < 0) return 1;  // the end of job
    if ((rtn = SearchEngine->patternSearch(curr)) <
        0) {  // search patterns in the data buffer
        *LastErrCode = rtn;
        THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,
                              new DgcError(SPOS, "crypt failed[%d]", rtn)),
                -1);
    } else if (rtn > 0)
        NumPttns += rtn;

    unsigned char* cdbp =
        curr->DstDataPtr;  // the current detecting buffer pointer
    PccSegment* seg;
    curr->DstLength = 0;
    curr->SegList->rewind();

    while ((seg = curr->SegList->next())) {
        unsigned char* sp = curr->SrcDataPtr + seg->sOffset();
        if (seg->type() ==
            PccSegment::SEG_T_PTTN) {  // pattern segment => should be saved
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
    CryptQueue.put(curr);  // return the crypt buffers into the crypt queue
    CryptBuffers++;

    return 0;
}
