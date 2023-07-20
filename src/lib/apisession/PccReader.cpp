#include "PccReader.h"

dgt_void PccReader::in() throw(DgcExcept) {
    while ((CurrBuf = CryptBufList.get(&Waiter)) == 0) FreeListWaits++;
    // if file seek pointer 0 and header_flag = on,
    // reader is skip header size
    if (HeaderSize) {
        if (InStream->seek(0, SEEK_CUR) == 0) {
            InStream->seek(HeaderSize, SEEK_CUR);
            RemainBytes -= HeaderSize;
        }
        HeaderSize = 0;
    }

    dgt_sint32 nbytes = 0;
    if ((nbytes = InStream->recvData(CurrBuf->SrcDataPtr, CurrBuf->SrcLength)) <
        0) {  // empty file
        *LastErrCode = -66001;
        ATHROW(DgcError(SPOS, "recvData failed"));
    } else if (nbytes < CurrBuf->SrcLength) {
        CurrBuf->SrcLength = nbytes;
    }
    *(CurrBuf->SrcDataPtr + CurrBuf->SrcLength) =
        0;  // null terminating for pattern search
    if ((RemainBytes -= nbytes) < 0) {
        *LastErrCode = -66002;
        THROW(DgcBgmrExcept(
            DGC_EC_BG_INCOMPLETE,
            new DgcError(SPOS, "file not closed, getting smaller[%lld]",
                         RemainBytes)));
    }
}

dgt_sint32 PccReader::run() throw(DgcExcept) {
    dgt_uint8* cp = 0;
    dgt_sint32 buf_len = 0;
    if (*LastErrCode) return 1;
    if (RemainBytes) {
        // get the handover size of the CurrBuf
        dgt_sint32 handover_size =
            RemainBytes ? SearchEngine->getHandoverSize(CurrBuf) : 0;

        // get the next buffer
        while ((NextBuf = CryptBufList.get(&Waiter)) == 0) {
            if (StopFlag) return 1;
            if (*LastErrCode)
                return 1;  // added by ihjin for thread normal stop
            FreeListWaits++;
        }

        // copy the handover of CurrBuf to the next buffer
        cp = NextBuf->SrcDataPtr;
        buf_len = NextBuf->SrcLength;
        if (handover_size) {
            memcpy(NextBuf->SrcDataPtr,
                   CurrBuf->SrcDataPtr + CurrBuf->SrcLength - handover_size,
                   handover_size);
            cp += handover_size;
            buf_len -= handover_size;
            CurrBuf->SrcLength -=
                handover_size;  // decrease SrcLength by handover_size
            *(CurrBuf->SrcDataPtr + CurrBuf->SrcLength) =
                0;  // null terminating SrcDataPtr for pattern search
        }
        NextBuf->SrcLength = handover_size;
    }

    // put the CurrBuf into DataQueue for Ciphers
    if (RemainBytes == 0)
        CurrBuf->LastFlag = 1;  // 2017.09.13 added by shson for tail_line
    DataQueue.put(CurrBuf);
    ReadBuffers++;

    if (RemainBytes) {  // read data into the next buffer
        dgt_sint32 nbytes = 0;
        if ((nbytes = InStream->recvData(cp, buf_len)) < 0) {
            *LastErrCode = -66003;
            ATHROWnR(DgcError(SPOS, "recvData failed"), -1);
        } else if (nbytes == 0 && RemainBytes > 0) {
            *LastErrCode = -66004;
            THROWnR(
                DgcBgmrExcept(
                    DGC_EC_BG_INCOMPLETE,
                    new DgcError(SPOS, "file not closed, getting smaller[%lld]",
                                 RemainBytes)),
                -1);
        }
        if ((RemainBytes -= nbytes) < 0) {
            *LastErrCode = -66005;
            THROWnR(
                DgcBgmrExcept(
                    DGC_EC_BG_INCOMPLETE,
                    new DgcError(SPOS, "file not closed, getting bigger[%lld]",
                                 RemainBytes)),
                -1);
        }
        NextBuf->SrcLength += nbytes;
        *(NextBuf->SrcDataPtr + NextBuf->SrcLength) =
            0;  // null terminating for pattern search
    }

    CurrBuf = NextBuf;
    NextBuf = 0;
    if (CurrBuf == 0 || CurrBuf->SrcLength == 0) return 1;  // the end of reader
    return 0;
}

dgt_sint32 PccReader::readAndHandover(PccCryptBuffer** rtn_buf) throw(
    DgcExcept) {
    if (StopFlag) return 1;
    // if file seek pointer 0 and header_flag = on,
    // reader is skip header size
    if (HeaderSize) {
        if (StreamFlag == 0 && InStream->seek(0, SEEK_CUR) == 0) {
            InStream->seek(HeaderSize, SEEK_CUR);
            RemainBytes -= HeaderSize;
        }
        HeaderSize = 0;
    }

    if (*rtn_buf) {
        // return the previous buffer for initialization
        CryptBufList.put(*rtn_buf);
        *rtn_buf = 0;
    }
    // read first buffer
    if (CurrBuf == 0 && RemainBytes) {
        while ((CurrBuf = CryptBufList.get(&Waiter)) == 0) FreeListWaits++;
        dgt_sint32 nbytes = 0;
        if ((nbytes = InStream->recvData(
                 CurrBuf->SrcDataPtr, CurrBuf->SrcLength)) < 0) {  // empty file
            *LastErrCode = PFC_RD_ERR_CODE_RECV_DATA_FAILED;
            ATHROWnR(DgcError(SPOS, "recvData failed"), -1);
        } else if (nbytes < CurrBuf->SrcLength) {
            if (StreamFlag == 0)
                CurrBuf->SrcLength = nbytes;
            else
                memset(CurrBuf->SrcDataPtr + nbytes, 0,
                       CurrBuf->SrcLength - nbytes);
        }
        *(CurrBuf->SrcDataPtr + CurrBuf->SrcLength) =
            0;  // null terminating for pattern search
        if ((RemainBytes -= nbytes) < 0) {
            if (StreamFlag == 0) {
                *LastErrCode = PFC_RD_ERR_CODE_FILE_NOT_CLOSED;
                THROWnR(DgcBgmrExcept(
                            DGC_EC_BG_INCOMPLETE,
                            new DgcError(
                                SPOS, "file not closed, getting bigger[%lld]",
                                RemainBytes)),
                        -1);
            } else if (StreamFlag == 1) {
                nbytes += RemainBytes;
                RemainBytes = 0;
            }
        }
    }
    if (RemainBytes == 0 && CurrBuf)
        CurrBuf->LastFlag = 1;  // 2017.09.13 added by shson for tail_line
    dgt_sint32 handover_size = 0;
    NextBuf = 0;
    if (RemainBytes) {  // handover to and read into the next buffer
        // handover

        while ((NextBuf = CryptBufList.get(&Waiter)) == 0) FreeListWaits++;
        handover_size = SearchEngine->getHandoverSize(CurrBuf);
        dgt_uint8* cp = NextBuf->SrcDataPtr;
        dgt_sint32 buf_len = NextBuf->SrcLength;
        if (handover_size) {  // copy handover from CurrBuf to next
            memcpy(NextBuf->SrcDataPtr,
                   CurrBuf->SrcDataPtr + CurrBuf->SrcLength - handover_size,
                   handover_size);
            cp += handover_size;
            buf_len -= handover_size;
            CurrBuf->SrcLength -=
                handover_size;  // decrease SrcLength by handover_size
            *(CurrBuf->SrcDataPtr + CurrBuf->SrcLength) =
                0;  // null terminating SrcDataPtr for pattern search
        }
        NextBuf->SrcLength = handover_size;
        ReadBuffers++;
        // read into remains buffer
        dgt_sint32 nbytes;
        if ((nbytes = InStream->recvData(cp, buf_len)) < 0) {
            *LastErrCode = PFC_RD_ERR_CODE_RECV_DATA_FAILED;
            ATHROWnR(DgcError(SPOS, "recvData failed"), -1);
        } else if (nbytes == 0 && RemainBytes > 0) {
            *LastErrCode = PFC_RD_ERR_CODE_FILE_NOT_CLOSED;
            THROWnR(
                DgcBgmrExcept(
                    DGC_EC_BG_INCOMPLETE,
                    new DgcError(SPOS, "file not closed, getting smaller[%lld]",
                                 RemainBytes)),
                -1);
        }
        if ((RemainBytes -= nbytes) < 0) {
            if (StreamFlag == 0) {
                *LastErrCode = PFC_RD_ERR_CODE_FILE_NOT_CLOSED;
                THROWnR(DgcBgmrExcept(
                            DGC_EC_BG_INCOMPLETE,
                            new DgcError(
                                SPOS, "file not closed, getting bigger[%lld]",
                                RemainBytes)),
                        -1);
            } else if (StreamFlag == 1) {
                nbytes += RemainBytes;
                RemainBytes = 0;
            }
        }
        if (StreamFlag == 0)
            NextBuf->SrcLength += nbytes;
        else {
            NextBuf->SrcLength += buf_len;
            memset(NextBuf->SrcDataPtr + nbytes, 0,
                   NextBuf->SrcLength - nbytes);
        }
        *(NextBuf->SrcDataPtr + NextBuf->SrcLength) =
            0;  // null terminating for pattern search
    }
    *rtn_buf = CurrBuf;
    CurrBuf = NextBuf;
    if (*rtn_buf == 0) return 0;
    return 1;
}
