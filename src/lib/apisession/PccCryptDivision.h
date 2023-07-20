/*******************************************************************
 *   File Type          :       File Cryptor class declaration
 *   Classes            :       PccCryptDivision
 *   Implementor        :       chchung
 *   Create Date        :       2017. 05. 14
 *   Description        :
 *   Modification history
 *   date                    modificationf
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_CRYPT_DIVISION_H
#define PCC_CRYPT_DIVISION_H

#include "PccCryptUnit.h"
#include "PccDetectUnit.h"
#include "PccFileMerger.h"
#include "PccFileSpliter.h"

class PccCryptDivision : public DgcObject {
   private:
    PccSearchEngineFactory& SearchEngineFactory;
    PccCryptorFactory& CryptorFactory;
    PccHeaderManager& HeaderManager;
    dgt_sint32 LastErrCode;
    dgt_sint64 OutBufLen;
    dgt_sint64 NumPttns;
    dgt_sint64 InFileSize;  // added by mwpark 2017.06.28 for filesize logging
    dgt_sint64
        OutFileSize;  // added by shson  2017.07.02 for collecting statistic
    dgt_sint32 IsSkip;
    DgcMemRows* DetectData;

   protected:
   public:
    PccCryptDivision(PccSearchEngineFactory& sef, PccCryptorFactory& cf,
                     PccHeaderManager& hm);
    virtual ~PccCryptDivision();

    inline dgt_sint64 outBufLen() { return OutBufLen; }
    inline dgt_sint64 numPttns() { return NumPttns; }
    inline dgt_sint64 inFileSize() { return InFileSize; }
    inline dgt_sint64 outFileSize() { return OutFileSize; }
    inline dgt_sint32 isSkip() { return IsSkip; }

    dgt_sint32 crypt(const dgt_schar* in_file, const dgt_schar* out_file,
                     dgt_uint8 force_target_write, dgt_schar* err_string);
    dgt_sint32 detect(const dgt_schar* in_file, DgcMemRows* detect_data,
                      dgt_schar* err_string);
};
#endif
