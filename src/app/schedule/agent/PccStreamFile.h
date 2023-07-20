/*******************************************************************
 *   File Type          :       File Cipher Agent classes declaration
 *   Classes            :       PccStreamFile
 *   Implementor        :       shson
 *   Create Date        :       2019. 07. 03
 *   Description        :
 *   Modification history
 *   date                    modification
 --------------------------------------------------------------------

 ********************************************************************/
#ifndef PCC_STREAM_FILE_H
#define PCC_STREAM_FILE_H

#include "DgcObject.h"

class PccStreamFile : public DgcObject {
   private:
    dgt_sint64 FileId;       // file id, inode number in linux and unix
    dgt_sint64 DirId;        // dir id
    dgt_sint64 ZoneId;       // zone id
    dgt_sint64 SrcFileSize;  // file size
    dgt_sint64 DstFileSize;  // file size
    dgt_time LmTime;         // last modified time
    dgt_schar* SrcFileName;  // source file name
    dgt_schar* DstFileName;  // output file name
    dgt_sint32 SrcFileNameLen;
    dgt_sint32 DstFileNameLen;
    dgt_sint32
        ErrCode;        // indicator if source and ouput file names are the same
    dgt_schar* ErrMsg;  // indicator if source and ouput file names are the same
   protected:
   public:
    static const dgt_sint32 INIT_FILE_NAME_LEN = 2048;
    static const dgt_sint32 EXTRA_FILE_NAME_LEN = 256;
    static const dgt_sint32 MAX_ERROR_MSG = 1024;
    PccStreamFile();
    virtual ~PccStreamFile();
    inline dgt_sint64 fileId() { return FileId; };
    inline dgt_sint64 dirId() { return DirId; };
    inline dgt_sint64 zoneId() { return ZoneId; };
    inline dgt_sint64 srcFileSize() { return SrcFileSize; };
    inline dgt_sint64 dstFileSize() { return DstFileSize; };
    inline dgt_time lmTime() { return LmTime; };
    inline const dgt_schar* srcFileName() { return SrcFileName; };
    inline const dgt_schar* dstFileName() { return DstFileName; };
    inline dgt_sint32 errCode() { return ErrCode; };
    inline const dgt_schar* errMsg() { return ErrMsg; };

    inline dgt_void setSrcFileSize(dgt_sint64 src_file_size) {
        SrcFileSize = src_file_size;
    };
    inline dgt_void setDstFileSize(dgt_sint64 dst_file_size) {
        DstFileSize = dst_file_size;
    };
    inline dgt_void setLmTime(dgt_time lm_time) { LmTime = lm_time; };
    inline dgt_void setErrCode(dgt_sint32 error_code) { ErrCode = error_code; };
    inline dgt_void setErrMsg(const dgt_schar* error_msg) {
        if (error_msg && strlen(error_msg) != 0) {
            if (ErrMsg == 0) ErrMsg = new dgt_schar[MAX_ERROR_MSG];
            memset(ErrMsg, 0, MAX_ERROR_MSG);
            strncpy(ErrMsg, error_msg, MAX_ERROR_MSG);
        }
    };
    dgt_void reset(dgt_sint64 file_id, dgt_sint64 dir_id, dgt_sint64 zone_id,
                   dgt_sint64 src_file_size, dgt_sint64 dst_file_size,
                   dgt_time lm_time, const dgt_schar* src_file_name,
                   const dgt_schar* dst_file_name, dgt_sint32 error_code,
                   const dgt_schar* error_msg);

    dgt_void copy(PccStreamFile* sf);
};

#endif
