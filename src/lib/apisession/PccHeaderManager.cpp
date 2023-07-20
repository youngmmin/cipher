#if 1
#define DEBUG
#endif

#include "PccHeaderManager.h"

PccHeaderManager::PccHeaderManager()
    : Version(0),
      EncryptCheckSum(0),
      OutFileSize(0),
      InFileSize(0),
      BufferSize(0),
      EncZoneId(0),
      KeyID(0),
      Reserved(0),
      HeaderFlag(0),
      HeaderSize(0),
      OutStream(0),
      Header(0) {}

PccHeaderManager::~PccHeaderManager() {
    if (Header) delete[] Header;
}

dgt_sint32 PccHeaderManager::checkHeader(DgcFileStream* in_stream,
                                         dgt_header_info* header_info) {
    dgt_sint32 file_indicator = 0;
    dgt_sint32 rtn = 0;
    dgt_uint8 fix_header[HEADER_SIZE2];
    dgt_sint32 nbyte = 0;
    memset(fix_header, 0, sizeof(fix_header));
    if (in_stream->fileSize() < (dgt_sint64)HEADER_SIZE1) {
        return 0;
    }
    if ((nbyte = in_stream->recvData(fix_header, sizeof(fix_header))) < 0) {
        ATHROWnR(DgcError(SPOS, "recvData failed "), -1);
    }
    Version = fix_header[0];
    if (Version == 1) {
        mcp4((dgt_uint8*)&EncryptCheckSum, fix_header + sizeof(Version));
        mcp8((dgt_uint8*)&OutFileSize,
             fix_header + sizeof(Version) + sizeof(EncryptCheckSum));
        rtn = compareCheckSum(
            in_stream->fileSize());  // rtn 1 : encrypt, 0 : text, -1 : broken
        if (rtn == PFC_HEADER_FILE_TYPE_ENCRYPT) HeaderSize = HEADER_SIZE1;
        if (rtn < 0) {
            if (rtn == PFC_HEADER_FILE_TYPE_BROKEN_FILE)
                ATHROWnR(DgcError(SPOS, "compareCheckSum Failed "), rtn);
            else if (rtn == PFC_HEADER_FILE_TYPE_ENCRYPT_IN_PROGRESS)
                ATHROWnR(DgcError(SPOS, "encryption is currently underway "),
                         rtn);
        }
    } else if (Version == 2 || Version == 3 || Version == 4) {
        mcp4((dgt_uint8*)&EncryptCheckSum, fix_header + sizeof(Version));
        mcp8((dgt_uint8*)&OutFileSize,
             fix_header + sizeof(Version) + sizeof(EncryptCheckSum));
        mcp8((dgt_uint8*)&InFileSize, fix_header + sizeof(Version) +
                                          sizeof(EncryptCheckSum) +
                                          sizeof(OutFileSize));
        mcp4((dgt_uint8*)&BufferSize,
             fix_header + sizeof(Version) + sizeof(EncryptCheckSum) +
                 sizeof(OutFileSize) + sizeof(InFileSize));
        mcp8((dgt_uint8*)&EncZoneId,
             fix_header + sizeof(Version) + sizeof(EncryptCheckSum) +
                 sizeof(OutFileSize) + sizeof(InFileSize) + sizeof(BufferSize));
        mcp8((dgt_uint8*)&KeyID, fix_header + sizeof(Version) +
                                     sizeof(EncryptCheckSum) +
                                     sizeof(OutFileSize) + sizeof(InFileSize) +
                                     sizeof(BufferSize) + sizeof(EncZoneId));
        mcp8((dgt_uint8*)&Reserved,
             fix_header + sizeof(Version) + sizeof(EncryptCheckSum) +
                 sizeof(OutFileSize) + sizeof(InFileSize) + sizeof(BufferSize) +
                 sizeof(EncZoneId) + sizeof(KeyID));
        rtn = compareCheckSum(
            in_stream->fileSize());  // rtn 1 : encrypt, 0 : text, -1 : broken
        if (rtn == PFC_HEADER_FILE_TYPE_ENCRYPT) HeaderSize = HEADER_SIZE2;
        if (rtn < 0) {
            if (rtn == PFC_HEADER_FILE_TYPE_BROKEN_FILE)
                ATHROWnR(DgcError(SPOS, "compareCheckSum Failed "), rtn);
            else if (rtn == PFC_HEADER_FILE_TYPE_ENCRYPT_IN_PROGRESS)
                ATHROWnR(DgcError(SPOS, "encryption is currently underway "),
                         rtn);
        }
    } else {
        // another version
        // text status
        rtn = 0;
    }
    if (header_info) {
        header_info->version = Version;
        header_info->encrypt_checksum = EncryptCheckSum;
        header_info->out_file_size = OutFileSize;
        header_info->in_file_size = InFileSize;
        header_info->buffer_size = BufferSize;
        header_info->enc_zone_id = EncZoneId;
        header_info->key_id = KeyID;
        header_info->reserved = Reserved;
    }
#if 0
	   printf("Version [%d], HeaderSize [%d] EncryptCheckSum [%u], OutFileSize [%lld], InFileSize [%lld], BufferSize [%d], EncZoneId [%lld] KeyID[%lld] Reserved [%lld]\n"
	   ,Version
	   ,HeaderSize
	   ,EncryptCheckSum
	   ,OutFileSize
	   ,InFileSize
	   ,BufferSize
	   ,EncZoneId
	   ,KeyID
	   ,Reserved);
#endif

    // reset file location indicator
    file_indicator = in_stream->seek(0, SEEK_SET);
    if (file_indicator != 0)
        ATHROWnR(DgcError(SPOS, "seek failed [%d]", file_indicator), -1);
    return rtn;
}

dgt_sint32 PccHeaderManager::checkHeader(dgt_schar* in_file,
                                         dgt_header_info* header_info) {
#ifndef WIN32
    DgcFileStream in(in_file, O_RDONLY);
#else
    DgcFileStream in(in_file, O_RDONLY | _O_BINARY);
#endif
    DgcExcept* e = 0;
    if ((e = EXCEPT)) {
        ATHROWnR(DgcError(SPOS, "DgcFileStream create failed [%s] ", in_file),
                 -1);
    }
    return checkHeader(&in, header_info);
}

dgt_uint32 PccHeaderManager::makeCheckSum() {
    dgt_uint32 check_sum = 0;
    dgt_schar special_string[20];
    memset(special_string, 0, sizeof(special_string));
    strcat(special_string, "sinsi17320*");

    check_sum = DgcCRC32::initCRC();
    DgcCRC32::calCRC(&check_sum, (dgt_uint8*)special_string,
                     strlen(special_string));
    check_sum = DgcCRC32::resultCRC(check_sum);

    return check_sum;
}

dgt_sint32 PccHeaderManager::compareCheckSum(dgt_sint64 file_size) {
    dgt_uint32 check_sum;
    // encrypt checksum compare
    check_sum = makeCheckSum();
    if (check_sum != EncryptCheckSum)
        return 0;  // text file
    else {
        if (file_size == OutFileSize)
            return PFC_HEADER_FILE_TYPE_ENCRYPT;  // encrypting file
        else if (OutFileSize == 0)
            THROWnR(DgcBgmrExcept(
                        DGC_EC_BG_INCOMPLETE,
                        new DgcError(SPOS,
                                     "encryption is currently underway file")),
                    PFC_HEADER_FILE_TYPE_ENCRYPT_IN_PROGRESS);  // be currently
                                                                // underway
        else
            THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,
                                  new DgcError(SPOS, "broken file")),
                    PFC_HEADER_FILE_TYPE_BROKEN_FILE);
    }
}

dgt_sint32 PccHeaderManager::writeRTHeader(DgcFileStream* out_stream,
                                           dgt_uint8 version) {
    OutStream = out_stream;
    if (version == 0) version = 3;
    initHeader(version);
    EncryptCheckSum = makeCheckSum();
    Header[0] = Version;
    mcp4(Header + sizeof(Version), (dgt_uint8*)&EncryptCheckSum);
    dgt_sint32 nbytes = 0;
    dgt_sint32 file_indicator = 0;
    file_indicator = out_stream->seek(0, SEEK_SET);
    if (file_indicator != 0)
        ATHROWnR(DgcError(SPOS, "seek failed [%d]", file_indicator), -1);
    if ((nbytes = OutStream->sendData(Header, HeaderSize)) < 0) {
        ATHROWnR(
            DgcError(SPOS, "sendData failed : HeaderSize [%d], WriteSize [%d]",
                     HeaderSize, nbytes),
            -1);
    }
    return 0;
}

dgt_sint32 PccHeaderManager::writeHeader(
    DgcFileStream* out_stream, dgt_uint8 version, dgt_sint64 infile_size,
    dgt_sint32 buffer_size, dgt_sint64 enc_zone_id, dgt_sint64 key_id) {
    OutStream = out_stream;
    if (version == 0) version = 1;
    initHeader(version);
    InFileSize = infile_size;
    BufferSize = buffer_size;
    EncZoneId = enc_zone_id;
    KeyID = key_id;
    dgt_sint32 nbytes = 0;
    dgt_sint32 file_indicator = 0;
#if 0
	dgt_uint32 test_checksum = 0;
	mcp4((dgt_uint8*)&test_checksum, (dgt_uint8*)(Header + sizeof(Version)));
	   printf("writeheader Version [%d], HeaderSize [%d] EncryptCheckSum [%u], OutFileSize [%lld], InFileSize [%lld], BufferSize [%d], EncZoneId [%lld] KeyID[%lld] Reserved [%lld] version [%d], checksum [%u]\n"
	   ,Version
	   ,HeaderSize
	   ,EncryptCheckSum
	   ,OutFileSize
	   ,InFileSize
	   ,BufferSize
	   ,EncZoneId
	   ,KeyID
	   ,Reserved
	   ,Header[0]
	   ,test_checksum);
#endif
    file_indicator = out_stream->seek(0, SEEK_SET);
    if (file_indicator != 0)
        ATHROWnR(DgcError(SPOS, "seek failed [%d]", file_indicator), -1);
    if ((nbytes = OutStream->sendData(Header, HeaderSize)) < 0) {
        ATHROWnR(
            DgcError(SPOS, "sendData failed : HeaderSize [%d], WriteSize [%d]",
                     HeaderSize, nbytes),
            -1);
    }
    return 0;
}

dgt_sint32 PccHeaderManager::commitHeader() {
    dgt_sint32 nbytes = 0;
    dgt_sint32 rtn = 0;
    dgt_sint32 file_indicator = 0;
    memset(Header, 0, HeaderSize);

    // EncryptCheckSum = makeCheckSum();
    OutFileSize = OutStream->fileSize();
    Header[0] = Version;

    if (Version == 1) {
        mcp4(Header + sizeof(Version), (dgt_uint8*)&EncryptCheckSum);
        mcp8(Header + sizeof(Version) + sizeof(EncryptCheckSum),
             (dgt_uint8*)&OutFileSize);
    } else if (Version == 2 || Version == 3 || Version == 4) {  // 2,3,4
        mcp4(Header + sizeof(Version), (dgt_uint8*)&EncryptCheckSum);
        mcp8(Header + sizeof(Version) + sizeof(EncryptCheckSum),
             (dgt_uint8*)&OutFileSize);
        mcp8(Header + sizeof(Version) + sizeof(EncryptCheckSum) +
                 sizeof(OutFileSize),
             (dgt_uint8*)&InFileSize);
        mcp4(Header + sizeof(Version) + sizeof(EncryptCheckSum) +
                 sizeof(OutFileSize) + sizeof(InFileSize),
             (dgt_uint8*)&BufferSize);
        mcp8(Header + sizeof(Version) + sizeof(EncryptCheckSum) +
                 sizeof(OutFileSize) + sizeof(InFileSize) + sizeof(BufferSize),
             (dgt_uint8*)&EncZoneId);
        mcp8(Header + sizeof(Version) + sizeof(EncryptCheckSum) +
                 sizeof(OutFileSize) + sizeof(InFileSize) + sizeof(BufferSize) +
                 sizeof(EncZoneId),
             (dgt_uint8*)&KeyID);
        mcp8(Header + sizeof(Version) + sizeof(EncryptCheckSum) +
                 sizeof(OutFileSize) + sizeof(InFileSize) + sizeof(BufferSize) +
                 sizeof(EncZoneId) + sizeof(KeyID),
             (dgt_uint8*)&Reserved);
#if 0
	dgt_uint32 test_checksum = 0;
	mcp4((dgt_uint8*)&test_checksum, (dgt_uint8*)(Header + sizeof(Version)));
	   printf("commit Version [%d], HeaderSize [%d] EncryptCheckSum [%u], OutFileSize [%lld], InFileSize [%lld], BufferSize [%d], EncZoneId [%lld] KeyID[%lld] Reserved [%lld] version [%d], checksum [%u]\n"
	   ,Version
	   ,HeaderSize
	   ,EncryptCheckSum
	   ,OutFileSize
	   ,InFileSize
	   ,BufferSize
	   ,EncZoneId
	   ,KeyID
	   ,Reserved
	   ,Header[0]
	   ,test_checksum);
#endif
    } else {
        THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,
                              new DgcError(SPOS, "broken file")),
                -1);
    }

    file_indicator = OutStream->seek(0, SEEK_SET);
    if (file_indicator != 0) {
        ATHROWnR(DgcError(SPOS, "seek failed [%d]", file_indicator), -1);
    }
    if ((nbytes = OutStream->sendData((dgt_uint8*)Header, HeaderSize)) < 0) {
        ATHROWnR(DgcError(SPOS, "sendData failed"), -1);
    }
    return 0;
}

dgt_void PccHeaderManager::setHeaderFlag(const dgt_schar* header_flag) {
    if (header_flag && !strncasecmp(header_flag, "on", 2)) {  // old header
        HeaderFlag = 1;
    } else if (header_flag &&
               !strncasecmp(header_flag, "V2on", 4)) {  // general header
        HeaderFlag = 2;
    } else if (header_flag &&
               !strncasecmp(header_flag, "V3on", 4)) {  // stream header
        HeaderFlag = 3;
    } else if (header_flag &&
               !strncasecmp(header_flag, "V4on", 4)) {  // kernel header
        HeaderFlag = 4;
    } else {
        HeaderFlag = 0;
    }
}

dgt_uint8* PccHeaderManager::getHeader() { return Header; }

dgt_void PccHeaderManager::initHeader(dgt_uint8 version) {
    // header V1
    //------------------------------------------------------------
    // Version(1byte) | EncryptCheckSum(4byte) | OutFileSize(8byte)
    //------------------------------------------------------------
    // header V2 V3 V4
    //-----------------------------------------------------------------------------------------------------------------------------------------
    // Version(1byte) | EncryptCheckSum(4byte) | OutFileSize(8byte) |
    // InFileSize(8byte) | BufferSize(4byte) | EncZoneId(8byte) | KeyID(8byte) |
    // Reserved(8byte)
    //-----------------------------------------------------------------------------------------------------------------------------------------

    if (version == 1) {
        Version = 1;
        HeaderSize = HEADER_SIZE1;
    } else if (version == 2) {
        Version = 2;
        HeaderSize = HEADER_SIZE2;
    } else if (version == 3) {
        Version = 3;
        HeaderSize = RT_HEADER_SIZE1;
    } else if (version == 4) {
        Version = 4;
        HeaderSize = HEADER_SIZE4;
    }
    EncryptCheckSum = makeCheckSum();
    OutFileSize = 0;
    InFileSize = 0;
    BufferSize = 0;
    if (Header) delete[] Header;
    Header = new dgt_uint8[HeaderSize];
    memset(Header, 0, HeaderSize);
    Header[0] = Version;
    mcp4(Header + sizeof(Version), (dgt_uint8*)&EncryptCheckSum);
#if 0
	dgt_uint32 test_checksum = 0;
	mcp4((dgt_uint8*)&test_checksum, (dgt_uint8*)(Header + sizeof(Version)));
	   printf("init Version [%d], HeaderSize [%d] EncryptCheckSum [%u], OutFileSize [%lld], InFileSize [%lld], BufferSize [%d], EncZoneId [%lld] KeyID[%lld] Reserved [%lld] version [%d], checksum [%u]\n"
	   ,Version
	   ,HeaderSize
	   ,EncryptCheckSum
	   ,OutFileSize
	   ,InFileSize
	   ,BufferSize
	   ,EncZoneId
	   ,KeyID
	   ,Reserved
	   ,Header[0]
	   ,test_checksum);
#endif
}
