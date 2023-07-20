/*******************************************************************
 *   File Type          :       File Cryptor class declaration
 *   Classes            :       PccFileMerger
 *   Implementor        :       chchung
 *   Create Date        :       2017. 05. 14
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_FILE_MERGER_H
#define PCC_FILE_MERGER_H

#include "PccRunStream.h"

class PccFileMerger : public DgcFileStream {
   private:
    static const dgt_sint32 COPY_BUF_SIZE = 1024000;
    PccCryptorFactory& CryptorFactory;
    dgt_sint32 BinaryFlag;
    const dgt_schar* FileName;
    dgt_sint64 RunSize;
    DgcFileStream* Runs[MAX_RUNS];
    dgt_sint32 NumRuns;
    dgt_uint8* CopyBuffer;

   protected:
   public:
    PccFileMerger(PccCryptorFactory& cf, const dgt_schar* file_name,
                  dgt_sint64 run_size, dgt_sint32 file_flag);
    virtual ~PccFileMerger();

    DgcFileStream* getRun(dgt_sint32 ith) throw(DgcExcept);
    dgt_sint32 mergeRuns() throw(DgcExcept);
    dgt_void removeRunFiles();
};

#endif
