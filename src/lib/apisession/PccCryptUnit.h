/*******************************************************************
 *   File Type          :       File Cryptor class declaration
 *   Classes            :       PccCryptUnit
 *   Implementor        :       chchung
 *   Create Date        :       2017. 05. 14
 *   Description        :
 *   Modification history
 *   date                    modificationf
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_CRYPT_UNIT_H
#define PCC_CRYPT_UNIT_H

#include "PccCipher.h"
#include "PccHeaderManager.h"
#include "PccReader.h"
#include "PccWriter.h"

class PccCryptUnit : public DgcWorker {
   private:
    DgcFileStream* InStream;
    DgcFileStream* OutStream;
    PccSearchEngineFactory& SearchEngineFactory;
    PccCryptorFactory& CryptorFactory;
    PccHeaderManager& HeaderManager;
    dgt_sint32* LastErrCode;
    dgt_schar* ErrString;
    PccFreeCryptBufList CryptBufList;
    PccCryptBufFifoQueue DataQueue;
    PccCryptList CryptQueue;
    PccReader* Reader;
    PccCipher* Ciphers[MAX_CIPHERS];
    dgt_sint32 NumCiphers;
    PccWriter* Writer;
    dgt_sint64 OutBufLen;
    dgt_sint64 InFileSize;  // added by shson for stream encryption 2019.06.28

    virtual dgt_void in() throw(DgcExcept);
    virtual dgt_sint32 run() throw(DgcExcept);
    virtual dgt_void out() throw(DgcExcept);

   protected:
   public:
    PccCryptUnit(DgcFileStream* in, DgcFileStream* out,
                 PccSearchEngineFactory& sef, PccCryptorFactory& cf,
                 PccHeaderManager& hm, dgt_sint32* last_err_code);
    virtual ~PccCryptUnit();

    inline void setInFileSize(dgt_sint64 in_file_size) {
        InFileSize = in_file_size;
    };
    inline dgt_sint64 outBufLen() { return OutBufLen; };
    inline const dgt_schar* errString() { return ErrString; };
    dgt_sint32 crypt() throw(DgcExcept);
};

#endif
