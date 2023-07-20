/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PcaCredentials
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 4. 24
 *   Description        :       credentials for key server connection
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcaCredentials.h"

dgt_void PcaCredentials::generateKey(const dgt_schar* credentials_pw) {
    dgt_schar key_seed[33] = {23,  84, 219, 42, 3,   59, 5,  232, 50,  89, 34,
                              202, 95, 7,   93, 123, 18, 7,  102, 9,   23, 103,
                              4,   66, 99,  82, 7,   69, 31, 204, 111, 82, 71};
    if (credentials_pw && *credentials_pw)
        for (dgt_uint32 i = 0; i < strlen(credentials_pw); i++)
            key_seed[i] = credentials_pw[i];
    for (dgt_sint32 i = 0; i < 32; i++)
        if (i % 2)
            key_seed[i] |= key_seed[i + 1];
        else
            key_seed[i] &= key_seed[i + 1];
    memcpy(KeySeed, key_seed, 33);
}

PcaCredentials::PcaCredentials() { cleanAttrs(); }

PcaCredentials::~PcaCredentials() {}

#include "PciCryptoIf.h"

dgt_sint32 PcaCredentials::generate(const dgt_schar* svc_name,
                                    const dgt_schar* user_id,
                                    const dgt_schar* password,
                                    const dgt_schar* credentials_pw) {
    dgt_schar tmp_buf[700];
    memset(tmp_buf, 0, 700);
    sprintf(tmp_buf,
            "s=%s\nu=%s\np=%s\nsh=%s\nip=%s\nmc=%s\nin=%s\ndn=%s\ndu=%s\nou=%"
            "s\npg=%s\nui=%s\n",
            svc_name, user_id, password, SvcHome, IP, MAC, InstanceName, DbName,
            DbUser, OsUser, Program, OrgUserID);
    PCI_Context ctx;
    generateKey(credentials_pw);
    PCI_initContext(&ctx, (dgt_uint8*)KeySeed, 256, PCI_CIPHER_AES,
                    PCI_EMODE_CBC, PCI_IVT_PIV1, 0, 1, 1);
    dgt_sint32 rtn = 0;
    dgt_uint32 dst_len = 1023;
    if ((rtn = PCI_encrypt(&ctx, (dgt_uint8*)tmp_buf, strlen(tmp_buf),
                           (dgt_uint8*)Credentials, &dst_len)) < 0)
        strncpy(ErrMsg, PCI_getErrMsg(&ctx), 255);
    return rtn;
}

#include "PcaNameValuePair.h"

dgt_sint32 PcaCredentials::parse(const dgt_schar* credentials,
                                 const dgt_schar* credentials_pw) {
    //
    // decrypt credentials
    //
    cleanAttrs();
    strncpy(Credentials, credentials, 1023);
    generateKey(credentials_pw);
    PCI_Context ctx;
    PCI_initContext(&ctx, (dgt_uint8*)KeySeed, 256, PCI_CIPHER_AES,
                    PCI_EMODE_CBC, PCI_IVT_PIV1, 0, 1, 1);
    dgt_schar dst_buf[700];
    dgt_uint32 dst_len = 700;
    dgt_sint32 rtn = 0;
    memset(dst_buf, 0, 700);
    if ((rtn = PCI_decrypt(&ctx, (dgt_uint8*)Credentials, strlen(Credentials),
                           (dgt_uint8*)dst_buf, &dst_len)) < 0) {
        strncpy(ErrMsg, PCI_getErrMsg(&ctx), 255);
        return rtn;
    }
    //
    // parse credentials and set connection attributes
    //
    PcaNameValuePair nvp;
    if ((rtn = nvp.parse(dst_buf))) {
        strncpy(ErrMsg, nvp.errMsg(), 255);
        return rtn;
    }
    dgt_schar* val;
    if ((val = nvp.getValue("s"))) {
        strncpy(SvcName, val, 32);
    } else {
        strncpy(ErrMsg, "invalid credentials, no service name", 255);
        return PCD_ERR_INVALID_CREDENTIALS;
    }
    if ((val = nvp.getValue("u"))) {
        strncpy(UserID, val, 32);
    } else {
        strncpy(ErrMsg, "invalid credentials, no user ID", 255);
        return PCD_ERR_INVALID_CREDENTIALS;
    }
    if ((val = nvp.getValue("p"))) {
        strncpy(Password, val, 32);
    } else {
        strncpy(ErrMsg, "invalid credentials, no password", 255);
        return PCD_ERR_INVALID_CREDENTIALS;
    }
    //
    // added by chchung, 2012.11.01, to get session attributes from credentials
    //
    if ((val = nvp.getValue("sh"))) strncpy(SvcHome, val, 128);
    if ((val = nvp.getValue("ip"))) strncpy(IP, val, 64);
    if ((val = nvp.getValue("mc"))) strncpy(MAC, val, 64);
    if ((val = nvp.getValue("in"))) strncpy(InstanceName, val, 32);
    if ((val = nvp.getValue("dn"))) strncpy(DbName, val, 32);
    if ((val = nvp.getValue("du"))) strncpy(DbUser, val, 32);
    if ((val = nvp.getValue("ou"))) strncpy(OsUser, val, 32);
    if ((val = nvp.getValue("pg"))) strncpy(Program, val, 128);
    if ((val = nvp.getValue("ui"))) strncpy(OrgUserID, val, 32);
    return 0;
}
