/*******************************************************************
 *   File Type          :       File Cryption Program.
 *   Classes            :       PccFileSpliter
 *   Implementor        :       chchung
 *   Create Date        :       2017. 05. 14
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccFileSpliter.h"

PccFileSpliter::PccFileSpliter(const dgt_schar* file_name,
                               PccPttnSearchEngine* se, PccCryptorFactory& cf)
#ifndef WIN32
    : DgcFileStream(file_name, O_RDONLY),
      FileName(file_name),
      SearchEngine(se),
      CryptorFactory(cf),
      CurrOffset(0),
      CurrRuns(0)
#else
    : DgcFileStream(file_name, O_RDONLY | _O_BINARY),
      FileName(file_name),
      SearchEngine(se),
      CryptorFactory(cf),
      CurrOffset(0),
      CurrRuns(0)
#endif
{
    if (EXCEPT) {
        FileName = file_name;
        CurrOffset = 0;
        CurrRuns = 0;
        ATHROW(DgcError(SPOS, "creating file_spliter failed"));
    } else {
        if (DgcFileStream::fileSize() == 0) {
            RunSize = 0;
            NumRuns = 0;
        } else if (CryptorFactory.runSize() == 0) {
            RunSize = DgcFileStream::fileSize();
            NumRuns = 1;
        } else {
#ifndef WIN32
            if ((NumRuns = (dgt_sint32)floor(DgcFileStream::fileSize() /
                                             CryptorFactory.runSize())) == 0)
                NumRuns = 1;
            RunSize = DgcFileStream::fileSize() / NumRuns;
#else
            NumRuns = 1;
#endif

            for (dgt_sint32 i = 0; i < MAX_RUNS; i++) Runs[i] = 0;

            // run_size should be multiple of buffer size for decrypt
            dgt_sint64 run_adjust_size = 0;
            if (fileSize() > CryptorFactory.bufferSize() &&
                (run_adjust_size = RunSize % CryptorFactory.bufferSize())) {
                RunSize -= run_adjust_size;
            }
            if ((RunSize * NumRuns - RunSize) > fileSize()) NumRuns--;
            if ((RunSize * NumRuns) < fileSize()) NumRuns++;
        }
    }
}

PccFileSpliter::~PccFileSpliter() {
    for (dgt_sint32 i = 0; i < CurrRuns; i++) {
        if (Runs[i]) delete Runs[i];
    }
}

dgt_sint32 PccFileSpliter::computeNextOffset() throw(DgcExcept) {
    PccCryptBuffer crypt_buf;
    memset(&crypt_buf, 0, sizeof(crypt_buf));
    crypt_buf.SrcLength = SearchEngine->maxHandoverSize();
    dgt_uint8* buffer = new dgt_uint8[crypt_buf.SrcLength + 1];
    memset(buffer, 0, crypt_buf.SrcLength + 1);
    crypt_buf.SrcDataPtr = buffer;
    if (DgcFileStream::seek(CurrOffset, SEEK_SET) <
        0) {  // move to the next run's starting point
        delete buffer;
        ATHROWnR(DgcError(SPOS, "seek failed"), -1);
    }
    dgt_sint32 rbytes;
    if ((rbytes = DgcFileStream::recvData(buffer, crypt_buf.SrcLength)) <
        0) {  // read a buffer
        delete buffer;
        ATHROWnR(DgcError(SPOS, "recvData failed"), -1);
    } else {
        crypt_buf.SrcLength = rbytes;
    }
    CurrOffset += (crypt_buf.SrcLength - SearchEngine->getHandoverSize(
                                             &crypt_buf));  // adjust CurrOffset
    delete buffer;
    return 0;
}

dgt_void PccFileSpliter::resetCurrOffset() {
    for (dgt_sint32 i = 0; i < CurrRuns; i++) {
        if (Runs[i]) delete Runs[i];
    }
    CurrOffset = 0;
    CurrRuns = 0;
}

DgcFileStream* PccFileSpliter::getRun() throw(DgcExcept) {
    if (CurrOffset >= DgcFileStream::fileSize()) return 0;  // the end of run
    dgt_sint64 start_offset = CurrOffset;
    if ((CurrOffset += RunSize) >= DgcFileStream::fileSize()) {  // the last run
        CurrOffset = DgcFileStream::fileSize();
    } else if (SearchEngine->needHandover()) {
        if (computeNextOffset() < 0) {
            ATHROWnR(DgcError(SPOS, "computeNextOffset failed"), 0);
        }
    }
#ifndef WIN32
    PccRunStream* rtn_run = new PccRunStream(
        FileName, O_RDONLY, 0666, start_offset, CurrOffset - start_offset);
#else
    PccRunStream* rtn_run =
        new PccRunStream(FileName, O_RDONLY | _O_BINARY, 0666, start_offset,
                         CurrOffset - start_offset);
#endif
    ATHROWnR(DgcError(SPOS, "open[%s] failed", FileName), 0);
    Runs[CurrRuns++] = rtn_run;
    return rtn_run;
}
