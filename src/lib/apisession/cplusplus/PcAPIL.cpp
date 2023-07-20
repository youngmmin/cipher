/*******************************************************************
 *   File Type          :       interface definition
 *   Classes            :       PcAPIL
 *   Implementor        :       mwpark
 *   Create Date        :       2015. 10. 20
 *   Description        :       petra cipher API Logging
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcAPIL.h"

#include <stdio.h>

void petracipher_version() {
    printf("Petra Cipher v3.2.%d\n", LIBRARY_VERSION);
    printf("Copyright (c) 2023 Sinsiway. All rights reserved.\n");
    printf(
        "Unauthorized use, reproduction, distribution, or modification of this "
        "software is strictly prohibited.\n\n");
}

#include "PcaApiSessionPool.h"

int PcAPI_initialize(char *info_file_path, char *credentials_pw) {
    return PcaApiSessionPool::initialize(info_file_path, credentials_pw);
}

int PcAPI_getSession(const char *client_ip) {
    return PcaApiSessionPool::getApiSession(client_ip, "", "", "", "", "", 0);
}

int PcAPI_encrypt(int api_sid, long long enc_col_id, unsigned char *src,
                  int src_len, unsigned char *dst, unsigned int *dst_len) {
    PcaApiSession *session = PcaApiSessionPool::getApiSession(api_sid);
    if (!session) return PcAPI_ERR_INVALID_SID;
    return session->encrypt(enc_col_id, src, src_len, dst, dst_len);
}

int PcAPI_encrypt_name(int api_sid, const char *enc_col_name,
                       unsigned char *src, int src_len, unsigned char *dst,
                       unsigned int *dst_len) {
    PcaApiSession *session = PcaApiSessionPool::getApiSession(api_sid);
    if (!session) return PcAPI_ERR_INVALID_SID;
    return session->encrypt(enc_col_name, src, src_len, dst, dst_len);
}

int PcAPI_decrypt(int api_sid, long long enc_col_id, unsigned char *src,
                  int src_len, unsigned char *dst, unsigned int *dst_len) {
    PcaApiSession *session = PcaApiSessionPool::getApiSession(api_sid);
    if (!session) return PcAPI_ERR_INVALID_SID;
    return session->decrypt(enc_col_id, src, src_len, dst, dst_len);
}

int PcAPI_decrypt_name(int api_sid, const char *enc_col_name,
                       unsigned char *src, int src_len, unsigned char *dst,
                       unsigned int *dst_len) {
    PcaApiSession *session = PcaApiSessionPool::getApiSession(api_sid);
    if (!session) return PcAPI_ERR_INVALID_SID;
    return session->decrypt(enc_col_name, src, src_len, dst, dst_len);
}

int PcAPI_getErrCode(int api_sid) {
    PcaApiSession *session = PcaApiSessionPool::getApiSession(api_sid);
    if (!session) return PcAPI_ERR_INVALID_SID;
    return session->getErrCode();
}

#include "PccFileCryptor.h"

int PcAPI_cryptFile(int api_sid, const char *parameters,
                    const char *in_file_path, const char *out_file_path) {
    PccFileCryptor cryptor;
    if (cryptor.crypt(api_sid, parameters, in_file_path, out_file_path) < 0) {
        int rtn = cryptor.errCode();
        if (rtn != PFC_DVS_ERR_CODE_ZERO_FILE_SIZE) {
            printf("crypt failed: %s - %d\n", cryptor.errString(),
                   cryptor.errCode());
            return rtn;
        }
    }
    return 0;
}

int PcAPI_isEncrypted(const char *file_name) {
    return PccHeaderManager::isEncrypted(file_name);
}
