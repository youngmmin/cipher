#ifndef PCC_HEADER_MANAGER_H
#define PCC_HEADER_MANAGER_H

#include "DgcCRC32.h"
#include "DgcFileStream.h"
#include "PccCryptorFactory.h"
#include "PccFileCipherConstTypes.h"

class PccHeaderManager : public DgcObject {
   private:
   protected:  // added by faoji on 2018. 07. 08. to move private properties
               // into protected region
    dgt_uint8 Version;
    dgt_uint32 EncryptCheckSum;
    dgt_sint64 OutFileSize;
    dgt_sint64 InFileSize;
    dgt_sint32 BufferSize;
    dgt_sint64 EncZoneId;
    dgt_sint64 KeyID;
    dgt_sint64 Reserved;
    dgt_uint8 HeaderFlag;
    dgt_uint32 HeaderSize;
    DgcFileStream* OutStream;
    dgt_uint8* Header;

   public:
    PccHeaderManager();
    virtual ~PccHeaderManager();
    dgt_sint32 checkHeader(dgt_schar* in_file,
                           dgt_header_info* header_info = 0);
    dgt_uint32 makeCheckSum();
    dgt_sint32 compareCheckSum(dgt_sint64 file_size);
#if 1  // make the below four methods virtual by faoji 2018. 07. 08.
    virtual dgt_sint32 checkHeader(DgcFileStream* in_stream,
                                   dgt_header_info* header_info = 0);
    virtual dgt_sint32 writeHeader(DgcFileStream* out_stream,
                                   dgt_uint8 version = 1,
                                   dgt_sint64 infile_size = 0,
                                   dgt_sint32 buffer_size = 0,
                                   dgt_sint64 enc_zone_id = 0,
                                   dgt_sint64 key_id = 0);
    virtual dgt_sint32 writeRTHeader(DgcFileStream* out_stream,
                                     dgt_uint8 version = 3);
    virtual dgt_sint32 commitHeader();
#endif
    dgt_sint64 inFileSize() {
        if (InFileSize) return InFileSize;
        return 0;
    }
    dgt_sint32 bufferSize() {
        if (BufferSize) return BufferSize;
        return 0;
    }
    dgt_sint64 encZoneId() {
        if (EncZoneId) return EncZoneId;
        return 0;
    }
    dgt_sint64 keyId() {
        if (KeyID) return KeyID;
        return 0;
    }
    dgt_uint16 headerSize() {
        if (HeaderSize) return HeaderSize;
        return 0;
    }
    dgt_uint8 headerFlag() { return HeaderFlag; }
    dgt_uint8 headerVersion() { return Version; }

    dgt_uint8* getHeader();
    dgt_void initHeader(dgt_uint8 version);

    dgt_void setHeaderFlag(const dgt_schar* header_flag);

    static dgt_sint32 isEncrypted(const dgt_schar* file_path,
                                  dgt_header_info* header_info = 0) {
        dgt_sint32 rtn = 0;
#ifndef WIN32
        DgcFileStream in(file_path, O_RDONLY);
#else
        DgcFileStream in(file_path, O_RDONLY | _O_BINARY);
#endif
        DgcExcept* e = 0;
        if ((e = EXCEPTnC)) {
            delete e;
            return PFC_FC_ERR_CODE_OPEN_IN_FILE_FAILED;
        }
        PccHeaderManager hm;
        rtn = hm.checkHeader(&in, header_info);
        return rtn;

    }  // -1 exception,  0 => text, 1 => encrypted
};

#endif
