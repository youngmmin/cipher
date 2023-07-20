/*******************************************************************
 *   File Type          :       interface declaration
 *   Classes            :       PcAPIL
 *   Implementor        :       mwpark
 *   Create Date        :       2015. 10. 20
 *   Description        :       petra cipher API Logging
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PC_APIL_H
#define PC_APIL_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
void __declspec(dllexport) petracipher_version();
#else
void petracipher_version();
#endif

#ifdef WIN32
int __declspec(dllexport)
    PcAPI_initialize(char* info_file_path, char* credentials_pw);
#else
int PcAPI_initialize(char* info_file_path, char* credentials_pw);
#endif

#ifdef WIN32
int __declspec(dllexport) PcAPI_getSession(const char* client_ip);
#else
int PcAPI_getSession(const char* client_ip);
#endif

#ifdef WIN32
int __declspec(dllexport)
    PcAPI_encrypt(int api_sid, long long enc_col_id, unsigned char* src,
                  int src_len, unsigned char* dst, unsigned int* dst_len);

#else
int PcAPI_encrypt(int api_sid, long long enc_col_id, unsigned char* src,
                  int src_len, unsigned char* dst, unsigned int* dst_len);
#endif

#ifdef WIN32
int __declspec(dllexport)
    PcAPI_encrypt_name(int api_sid, const char* enc_col_name,
                       unsigned char* src, int src_len, unsigned char* dst,
                       unsigned int* dst_len);
#else
int PcAPI_encrypt_name(int api_sid, const char* enc_col_name,
                       unsigned char* src, int src_len, unsigned char* dst,
                       unsigned int* dst_len);
#endif

#ifdef WIN32
int __declspec(dllexport)
    PcAPI_decrypt(int api_sid, long long enc_col_id, unsigned char* src,
                  int src_len, unsigned char* dst, unsigned int* dst_len);
#else
int PcAPI_decrypt(int api_sid, long long enc_col_id, unsigned char* src,
                  int src_len, unsigned char* dst, unsigned int* dst_len);
#endif

#ifdef WIN32
int __declspec(dllexport)
    PcAPI_decrypt_name(int api_sid, const char* enc_col_name,
                       unsigned char* src, int src_len, unsigned char* dst,
                       unsigned int* dst_len);
#else
int PcAPI_decrypt_name(int api_sid, const char* enc_col_name,
                       unsigned char* src, int src_len, unsigned char* dst,
                       unsigned int* dst_len);
#endif

#ifdef WIN32
int __declspec(dllexport) PcAPI_getErrCode(int api_sid);
#else
int PcAPI_getErrCode(int api_sid);
#endif

#ifdef WIN32
int __declspec(dllexport)
    PcAPI_cryptFile(int api_sid, const char* parameters,
                    const char* in_file_path, const char* out_file_path);
#else
int PcAPI_cryptFile(int api_sid, const char* parameters,
                    const char* in_file_path, const char* out_file_path);
#endif

#ifdef WIN32
int __declspec(dllexport) PcAPI_isEncrypted(const char* file_name);
#else
int PcAPI_isEncrypted(const char* file_name);
#endif

#ifdef __cplusplus
}
#endif

static const int PcAPI_DECRYPT_BUF_SIZE = 2097152;

static const int PcAPI_ERR_UNSUPPORTED_KEY_SIZE = -30101;
static const int PcAPI_ERR_UNSUPPORTED_ENC_MODE = -30102;
static const int PcAPI_ERR_UNSUPPORTED_CIPHER_TYPE = -30103;
static const int PcAPI_ERR_ENC_DATA_TOO_SHORT = -30104;
static const int PcAPI_ERR_OUT_BUFFER_TOO_SHORT = -30105;
static const int PcAPI_ERR_UNSUPPORTED_DIGEST_LEN = -30106;
static const int PcAPI_ERR_INVALID_ENC_DATA_LEN = -30107;
static const int PcAPI_ERR_B64_FORMAT_ERROR = -30108;
static const int PcAPI_ERR_ARIA_KEY_MAKING_ERROR = -30109;
static const int PcAPI_ERR_INVALID_ENC_START_POS = -30110;
static const int PcAPI_ERR_INVALID_PARAM_VALUE = -30111;
static const int PcAPI_ERR_EVP_FAILED = -30112;
static const int PcAPI_ERR_SFC_FAILED = -30113;
static const int PcAPI_ERR_INVALID_IV_TYPE = -30114;
static const int PcAPI_ERR_NO_ENCRYPT_PRIV = -30301;
static const int PcAPI_ERR_INVALID_SID = -30302;
static const int PcAPI_ERR_INVALID_HOST = -30303;
static const int PcAPI_ERR_SOCKET_ERROR = -30304;
static const int PcAPI_ERR_CONNECT_ERROR = -30305;
static const int PcAPI_ERR_WRITE_ERROR = -30306;
static const int PcAPI_ERR_READ_ERROR = -30307;
static const int PcAPI_ERR_BUF_OVERFLOW = -30308;
static const int PcAPI_ERR_SESS_LOCK_FAIL = -30309;
static const int PcAPI_ERR_SVR_SESS_LOCK_FAIL = -30310;
static const int PcAPI_ERR_NO_SVR_SESSION = -30311;
static const int PcAPI_ERR_NO_FREE_SVR_SESSION = -30312;
static const int PcAPI_ERR_NO_EMPTY_SPACE = -30313;
static const int PcAPI_ERR_PARSE_ERROR = -30316;
static const int PcAPI_ERR_FILE_IO_ERROR = -30317;
static const int PcAPI_ERR_APPROVE_REJECTED = -30318;
static const int PcAPI_ERR_NAME_NOT_FOUND = -30351;
static const int PcAPI_ERR_AMBIGUOUS_NAME = -30352;
static const int PcAPI_ERR_COLUMN_NOT_FOUND = -30353;
static const int PcAPI_ERR_KEY_NOT_FOUND = -30354;
static const int PKSS_SESSION_NOT_FOUND = -30701;

#endif /* PCCAPI_H */
