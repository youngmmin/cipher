/*******************************************************************
 *   File Type          :       declaration
 *   Classes            :       file cipher constants and types
 *   Implementor        :       jhpark
 *   Create Date        :       2017. 11. 06
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------
********************************************************************/
#ifndef PCC_FILE_CIPHER_CONST_TYPE_H
#define PCC_FILE_CIPHER_CONST_TYPE_H

#include "DgcObject.h"

static const dgt_sint32 MAX_CIPHERS = 1024;
static const dgt_sint32 MAX_RUNS = 1024;
static const dgt_sint32 MAX_ERR_STRING = 1025;

static const dgt_uint8 USE_KEY_TYPE_ENC_NAME = 1;
static const dgt_uint8 USE_KEY_TYPE_VIRTUAL_KEY = 2;

static const dgt_sint32 HEADER_SIZE1 = 13;
static const dgt_sint32 HEADER_SIZE2 = 49;
static const dgt_sint32 HEADER_SIZE4 = 49;
static const dgt_sint32 RT_HEADER_SIZE1 = 49;

typedef struct {
    dgt_uint8 version;
    dgt_uint32 encrypt_checksum;
    dgt_sint64 out_file_size;
    dgt_sint64 in_file_size;
    dgt_sint32 buffer_size;
    dgt_sint64 enc_zone_id;
    dgt_sint64 key_id;
    dgt_sint64 reserved;
} dgt_header_info;

// for header manager , check header return value
static const dgt_sint32 PFC_HEADER_FILE_TYPE_ORIGINAL = 0;
static const dgt_sint32 PFC_HEADER_FILE_TYPE_ENCRYPT = 1;
static const dgt_sint32 PFC_HEADER_FILE_TYPE_BROKEN_FILE = -1;
static const dgt_sint32 PFC_HEADER_FILE_TYPE_ENCRYPT_IN_PROGRESS = -3;

// for CryptorFactory, define crypt_mode
static const dgt_sint32 PFC_CRYPT_MODE_DECRYPT = 0;
static const dgt_sint32 PFC_CRYPT_MODE_ENCRYPT = 1;
static const dgt_sint32 PFC_CRYPT_MODE_VALIDATION = 2;
static const dgt_sint32 PFC_CRYPT_MODE_MIGRATION = 3;

static const dgt_sint32 PFC_DETECT_MODE_ALL = 0;
static const dgt_sint32 PFC_DETECT_MODE_TEXT = 1;
static const dgt_sint32 PFC_DETECT_MODE_IMAGE = 2;
static const dgt_sint32 PFC_DETECT_MODE_BINARY = 4;

// crypt unit err_code
static const dgt_sint32 PFC_UNIT_ERR_CODE_CRYPT_UNIT_ERROR = -66000;
static const dgt_sint32 PFC_UNIT_ERR_CODE_GET_ENGINE_FAILED = -66001;
static const dgt_sint32 PFC_UNIT_ERR_CODE_GET_CRYPTOR_FAILED = -66002;
static const dgt_sint32 PFC_UNIT_ERR_CODE_START_READER_FAILED = -66003;
static const dgt_sint32 PFC_UNIT_ERR_CODE_START_CIPHER_FAILED = -66004;
static const dgt_sint32 PFC_UNIT_ERR_CODE_START_WRITER_FAILED = -66005;

// reader err_code
static const dgt_sint32 PFC_RD_ERR_CODE_READER_ERROR = -66010;
static const dgt_sint32 PFC_RD_ERR_CODE_RECV_DATA_FAILED = -66011;
static const dgt_sint32 PFC_RD_ERR_CODE_FILE_NOT_CLOSED = -66012;

// writer err_code
static const dgt_sint32 PFC_WT_ERR_CODE_WRITER_ERROR = -66020;
static const dgt_sint32 PFC_WT_ERR_CODE_SEND_DATA_FAILED = -66021;

// search engine err_code
static const dgt_sint32 PFC_SE_ERR_CODE_SEARCH_ENGINE_ERROR = -66030;
static const dgt_sint32 PFC_SE_ERR_CODE_DILIMETER_NOT_FOUND = -66031;

// crypt division err_code
static const dgt_sint32 PFC_DVS_ERR_CODE_CRYPT_DIVISION_FAILED = -66040;
static const dgt_sint32 PFC_DVS_ERR_CODE_OPEN_IN_FILE_FAILED = -66041;
static const dgt_sint32 PFC_DVS_ERR_CODE_OPEN_OUT_FILE_FAILED = -66042;
static const dgt_sint32 PFC_DVS_ERR_CODE_ZERO_FILE_SIZE = -66043;
static const dgt_sint32 PFC_DVS_ERR_CODE_CHECK_HEADER_FAILED = -66044;
static const dgt_sint32 PFC_DVS_ERR_CODE_ALREADY_ENCRYPTED = -66045;
static const dgt_sint32 PFC_DVS_ERR_CODE_BROKEN_FILE = -66046;
static const dgt_sint32 PFC_DVS_ERR_CODE_ORIGINAL_FILE = -66047;
static const dgt_sint32 PFC_DVS_ERR_CODE_WRITE_HEADER_FAILED = -66048;
static const dgt_sint32 PFC_DVS_ERR_CODE_COMMIT_HEADER_FAILED = -66049;
static const dgt_sint32 PFC_DVS_ERR_CODE_INCOMPLETE_ENCRYPTION = -66050;
static const dgt_sint32 PFC_DVS_ERR_CODE_INCOMPLETE_DECRYPTION = -66051;
static const dgt_sint32 PFC_DVS_ERR_CODE_OPEN_FSPLITER_FAILED = -66052;
static const dgt_sint32 PFC_DVS_ERR_CODE_OPEN_FMERGER_FAILED = -66053;
static const dgt_sint32 PFC_DVS_ERR_CODE_GET_RUN_FAILED = -66054;
static const dgt_sint32 PFC_DVS_ERR_CODE_FSTREAM_NOT_ALLOCATED = -66055;
static const dgt_sint32 PFC_DVS_ERR_CODE_START_CRYPT_UNIT_FALED = -66056;
static const dgt_sint32 PFC_DVS_ERR_CODE_OUT_FILE_ALREADY_EXIST = -66057;

// file cryptor err_code
static const dgt_sint32 PFC_FC_ERR_CODE_FILE_CRYPTOR_ERROR = -66100;
static const dgt_sint32 PFC_FC_ERR_CODE_OPEN_LOG_FILE_FAILED = -66101;
static const dgt_sint32 PFC_FC_ERR_CODE_KEY_COL_NOT_DEFINED = -66102;
static const dgt_sint32 PFC_FC_ERR_CODE_KEY_NAME_NOT_DEFINED = -66103;
static const dgt_sint32 PFC_FC_ERR_CODE_UNSUPPORTED_PARAM = -66104;
static const dgt_sint32 PFC_FC_ERR_CODE_INVALID_PARAML_FORMAT = -66105;
static const dgt_sint32 PFC_FC_ERR_CODE_BUILD_PARAML_FAILED = -66106;
static const dgt_sint32 PFC_FC_ERR_CODE_BUILD_PARAMF_FAILED = -66107;
static const dgt_sint32 PFC_FC_ERR_CODE_IN_FILE_NOT_DEFINED = -66108;
static const dgt_sint32 PFC_FC_ERR_CODE_GET_API_SESSION_FAILED = -66109;
static const dgt_sint32 PFC_FC_ERR_CODE_OPEN_IN_FILE_FAILED = -66110;
static const dgt_sint32 PFC_FC_ERR_CODE_NO_PRIV_BY_SIZE_CTRL = -66111;
static const dgt_sint32 PFC_FC_ERR_CODE_IN_FILE_OUT_FILE_SAME = -66112;
static const dgt_sint32 PFC_FC_ERR_CODE_UNSUPPORTED_FILE_FORMAT = -66113;

#endif
