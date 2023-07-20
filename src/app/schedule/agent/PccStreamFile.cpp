/*******************************************************************
 *   File Type          :       File Cipher Agent classes definition
 *   Classes            :       PccStreamFile
 *   Implementor        :       shson
 *   Create Date        :       2019. 07. 03
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccStreamFile.h"

PccStreamFile::PccStreamFile() {
    FileId = 0;
    DirId = 0;
    ZoneId = 0;
    SrcFileSize = 0;
    DstFileSize = 0;
    SrcFileNameLen = DstFileNameLen = INIT_FILE_NAME_LEN;
    SrcFileName = new dgt_schar[SrcFileNameLen];
    DstFileName = new dgt_schar[DstFileNameLen];
    ErrCode = 0;
    ErrMsg = 0;
}

PccStreamFile::~PccStreamFile() {
    if (SrcFileName) delete SrcFileName;
    if (DstFileName) delete DstFileName;
    if (ErrMsg) delete ErrMsg;
}

dgt_void PccStreamFile::reset(dgt_sint64 file_id, dgt_sint64 dir_id,
                              dgt_sint64 zone_id, dgt_sint64 src_file_size,
                              dgt_sint64 dst_file_size, dgt_time lm_time,
                              const dgt_schar* src_file_name,
                              const dgt_schar* dst_file_name,
                              dgt_sint32 error_code,
                              const dgt_schar* error_msg) {
    FileId = file_id;
    DirId = dir_id;
    ZoneId = zone_id;
    SrcFileSize = src_file_size;
    DstFileSize = dst_file_size;
    LmTime = lm_time;
    if (ErrCode) ErrCode = 0;
    if (ErrMsg) {
        delete ErrMsg;
        ErrMsg = 0;
    }
    if (error_code) setErrCode(error_code);
    if (error_msg) setErrMsg(error_msg);

    // src_file_name setting
    dgt_sint32 src_file_name_len = dg_strlen(src_file_name);
    if (INIT_FILE_NAME_LEN < src_file_name_len) {
        delete SrcFileName;
        SrcFileName = 0;
        SrcFileNameLen = src_file_name_len + EXTRA_FILE_NAME_LEN;
        SrcFileName = new dgt_schar[SrcFileNameLen];
    }
    memset(SrcFileName, 0, SrcFileNameLen);
    strcpy(SrcFileName, src_file_name);

    // dst_file_name setting
    dgt_sint32 dst_file_name_len = dg_strlen(dst_file_name);
    if (INIT_FILE_NAME_LEN < dst_file_name_len) {
        delete DstFileName;
        DstFileName = 0;
        DstFileNameLen = dst_file_name_len + EXTRA_FILE_NAME_LEN;
        DstFileName = new dgt_schar[DstFileNameLen];
    }
    memset(DstFileName, 0, DstFileNameLen);
    strcpy(DstFileName, dst_file_name);
}

dgt_void PccStreamFile::copy(PccStreamFile* sf) {
    if (!sf) return;
    reset(sf->fileId(), sf->dirId(), sf->zoneId(), sf->srcFileSize(),
          sf->dstFileSize(), sf->lmTime(), sf->srcFileName(), sf->dstFileName(),
          sf->errCode(), sf->errMsg());
}
