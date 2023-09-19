/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcaPrivilege
 *   Implementor        :       chchung
 *   Create Date        :       2012. 4. 5.
 *   Description        :       petra cipher API key
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCA_PRIVILEGE_H
#define PCA_PRIVILEGE_H

#include "DgcBase64.h"
#include "DgcBgmrList.h"
#include "PcaHashNode.h"
#include "PcaIVPool.h"
#include "PcaKeyPool.h"
#include "PciCryptoIf.h"
#include "PciKeyMgrIf.h"
#include "PciMsgTypes.h"

class PcaPrivHolder : public DgcObject {
   private:
    static const dgt_sint32 MAX_PRIVs = 1024;
    pc_type_get_priv_out PrivInfo[MAX_PRIVs];
    dgt_sint64 EncColID[MAX_PRIVs];
    dgt_sint32 NumPrivs;
    dgt_sint32 CurrPrivNo;
    dgt_slock PoolLatch;

   protected:
   public:
    PcaPrivHolder() : NumPrivs(0), CurrPrivNo(0) {
        DgcSpinLock::unlock(&PoolLatch);
        memset((void*)&PrivInfo[0], 0, sizeof(PrivInfo));
    }
    virtual ~PcaPrivHolder() {}

    dgt_sint32 numPrivs() { return NumPrivs; }
    dgt_sint64 encColID(dgt_sint32 idx) { return EncColID[idx]; }
    pc_type_get_priv_out* privInfo(dgt_sint32 idx) { return &PrivInfo[idx]; }

    dgt_void rewind() { CurrPrivNo = 0; }
    dgt_sint64 nextEncColID() {
        if (CurrPrivNo < NumPrivs) return EncColID[CurrPrivNo++];
        return -1;
    }
    pc_type_get_priv_out* privInfo() {
        if (CurrPrivNo > 0) return &PrivInfo[CurrPrivNo - 1];
        return 0;
    }

    dgt_sint32 putPriv(dgt_sint64 enc_col_id, pc_type_get_priv_out* priv_out) {
        dgt_sint32 err_code = 0;
        if (DgcSpinLock::lock(&PoolLatch)) {
            err_code = -55001;
            PcaKeySvrSessionPool::logging(err_code,
                                          "locking the name pool failed");
        } else {
            if (NumPrivs >= MAX_PRIVs) {
                err_code = -55002;
                PcaKeySvrSessionPool::logging("out of privilige holder[%d]",
                                              MAX_PRIVs);
            } else {
                dgt_sint32 idx;
                for (idx = 0; idx < NumPrivs; idx++)
                    if (EncColID[idx] == enc_col_id) break;
                if (idx == NumPrivs) {
                    EncColID[NumPrivs] = enc_col_id;
                    memcpy((void*)&PrivInfo[NumPrivs], priv_out,
                           sizeof(pc_type_get_priv_out));
                    NumPrivs++;
                }
            }
            DgcSpinLock::unlock(&PoolLatch);
        }
        return err_code;
    }
};

class PcaPrivCompiler : public DgcObject {
   private:
    static const dgt_sint32 KEY_LEN = 65;
    pc_type_get_key_out KeyInfo;    // key info
    pc_type_get_priv_out PrivInfo;  // privilege info
#if 1  // added by chchung 2017.8.9 for export trailer info
    pc_type_get_trailer_out TrailerInfo;  // trailer info
#endif
    dgt_uint8 EncKey[KEY_LEN];
    PCI_Context EncContext;
    PCI_Context HashContext;
    dgt_schar TmpBuf[2049];
    dgt_schar EncColName[129];
    dgt_sint64 EncColID;

   protected:
   public:
    PcaPrivCompiler() {
        memset((void*)&KeyInfo, 0, sizeof(KeyInfo));
        memset((void*)&PrivInfo, 0, sizeof(PrivInfo));
        memset((void*)&TrailerInfo, 0, sizeof(TrailerInfo));
    }
    virtual ~PcaPrivCompiler() {}
    pc_type_get_key_out* keyInfo() { return &KeyInfo; }
    pc_type_get_priv_out* privInfo() { return &PrivInfo; }
    pc_type_get_trailer_out* trailerInfo() { return &TrailerInfo; }
    const dgt_schar* encColName() { return EncColName; }
    dgt_sint64 encColID() { return EncColID; }

    dgt_sint32 exportKeyInfo(const dgt_schar* enc_col_name,
                             dgt_sint64 enc_col_id, const dgt_schar* passwd,
                             dgt_schar* key_info_buf, dgt_uint32* buf_len) {
        dgt_schar b64_key[128 + 1];
        dgt_schar b64_week_map[25];
        dgt_schar hash_buf[128 + 1];
        dgt_uint32 hash_buf_len;
        dgt_schar trailer_buf[25];
        dgt_sint32 rtn;
        memset(b64_key, 0, 129);
        memset(b64_week_map, 0, 25);
        dgt_sint32 tmp_len = 128;
        tmp_len = DgcBase64::encode2(KeyInfo.key, 64, b64_key, tmp_len);
        memset(b64_key + tmp_len, 0, 1);
        tmp_len = 24;
        tmp_len =
            DgcBase64::encode2(PrivInfo.week_map, 12, b64_week_map, tmp_len);
        memset(b64_week_map + tmp_len, 0, 1);
        tmp_len = 24;
        tmp_len = DgcBase64::encode2((const dgt_uint8*)TrailerInfo.trailer_char,
                                     7, trailer_buf, tmp_len);
        memset(trailer_buf + tmp_len, 0, 1);
        sprintf(TmpBuf,
                "(ki=(enc_col_name=%s)(enc_col_id=%lld)"
                "(enc_length=%u)(key_size=%u)(cipher_type=%d)(enc_mode=%d)(iv_"
                "type=%d)(n2n_flag=%d)"
                "(b64_txt_enc_flag=%d)(enc_start_pos=%d)(mask_char=%s)(char_"
                "set=%s)(key=\"%s\")"
                "(key_id=%lld)(max_col_len=%u)(dec_alt_threshold=%u)(dec_"
                "masking_threshold=%u)"
                "(enc_priv=%d)(dec_priv=%d)(enc_no_priv_alert=%d)(dec_no_priv_"
                "alert=%d)(auth_fail_enc_priv=%d)"
                "(auth_fail_dec_priv=%d)(enc_audit_flag=%d)(dec_audit_flag=%d)("
                "col_type=%d)"
                "(ophuek_flag=%d)(multibyte_flag=%d)(week_map=\"%s\")"
                "(trailer_size=%d)(trailer_char=\"%s\"))",
                enc_col_name, enc_col_id, KeyInfo.enc_length, KeyInfo.key_size,
                KeyInfo.cipher_type, KeyInfo.enc_mode, KeyInfo.iv_type,
                KeyInfo.n2n_flag, KeyInfo.b64_txt_enc_flag,
                KeyInfo.enc_start_pos, KeyInfo.mask_char, KeyInfo.char_set,
                b64_key, PrivInfo.key_id, PrivInfo.max_col_len,
                PrivInfo.dec_alt_threshold, PrivInfo.dec_masking_threshold,
                PrivInfo.enc_priv, PrivInfo.dec_priv,
                PrivInfo.enc_no_priv_alert, PrivInfo.dec_no_priv_alert,
                PrivInfo.auth_fail_enc_priv, PrivInfo.auth_fail_dec_priv,
                PrivInfo.enc_audit_flag, PrivInfo.dec_audit_flag,
                PrivInfo.col_type, PrivInfo.ophuek_flag,
                PrivInfo.multibyte_flag, b64_week_map, TrailerInfo.trailer_size,
                trailer_buf);
        memset(hash_buf, 0, 129);
        sprintf(hash_buf, "(kh=\"");
        hash_buf_len = 124;
        PCI_initContext(&HashContext, 0, 256, PCI_CIPHER_SHA, 0, PCI_IVT_PIV1,
                        0, 1);
        if ((rtn = PCI_encrypt(&HashContext, (dgt_uint8*)TmpBuf, strlen(TmpBuf),
                               (dgt_uint8*)(hash_buf + 5), &hash_buf_len)) <
            0) {
            if (HashContext.err_code)
                PcaKeySvrSessionPool::logging(HashContext.err_code,
                                              HashContext.err_msg);
            return rtn;
        }
        strcat(hash_buf, "\")");
        hash_buf_len += 7;
        strncat(TmpBuf, hash_buf, hash_buf_len);

        dgt_schar dp11[17] = {53, 84, 39,  48, 39, 59, 51,  82, 55,
                              98, 34, 122, 95, 71, 93, 121, 0};
        dgt_uint8 soguem[17] = {153, 184, 93, 148, 33, 159, 55,  232, 51,
                                98,  134, 22, 59,  17, 39,  213, 0};
        if (passwd == 0 || strlen(passwd) == 0) passwd = dp11;
        dgt_uint32 ekl = 64;
        if ((rtn = PCI_PBKDF2(passwd, soguem, 16, EncKey, &ekl)) < 0) {
            PcaKeySvrSessionPool::logging(rtn, "PCI_PBKDF2 failed");
            return rtn;
        }

        PCI_initContext(&EncContext, EncKey, 32, PCI_CIPHER_AES, PCI_EMODE_CBC,
                        PCI_IVT_PIV1, 0, 1);
        if ((rtn = PCI_encrypt(&EncContext, (dgt_uint8*)TmpBuf, strlen(TmpBuf),
                               (dgt_uint8*)key_info_buf, buf_len)) < 0) {
            if (EncContext.err_code)
                PcaKeySvrSessionPool::logging(EncContext.err_code,
                                              EncContext.err_msg);
            return rtn;
        }
        return 0;
    }

    dgt_sint32 importKeyInfo(const dgt_schar* passwd,
                             const dgt_schar* key_info_buf,
                             dgt_uint32 buf_len) {
        dgt_schar dp11[17] = {53, 84, 39,  48, 39, 59, 51,  82, 55,
                              98, 34, 122, 95, 71, 93, 121, 0};
        dgt_uint8 soguem[17] = {153, 184, 93, 148, 33, 159, 55,  232, 51,
                                98,  134, 22, 59,  17, 39,  213, 0};
        if (passwd == 0 || strlen(passwd) == 0) passwd = dp11;
        dgt_uint32 ekl = 64;
        dgt_sint32 rtn = PCI_PBKDF2(passwd, soguem, 16, EncKey, &ekl);
        if (rtn < 0) return rtn;
        PCI_initContext(&EncContext, EncKey, 32, PCI_CIPHER_AES, PCI_EMODE_CBC,
                        PCI_IVT_PIV1, 0, 1);
        dgt_uint32 tmp_len = 2048;
        if ((rtn = PCI_decrypt(&EncContext, (dgt_uint8*)key_info_buf, buf_len,
                               (dgt_uint8*)TmpBuf, &tmp_len)) < 0) {
            if (EncContext.err_code)
                PcaKeySvrSessionPool::logging(EncContext.err_code,
                                              EncContext.err_msg);
            return rtn;
        }
        memset(TmpBuf + tmp_len, 0, 1);
        dgt_schar hash_buf[128 + 1];
        dgt_uint32 hash_buf_len;
        dgt_schar* hash_ptr;
        dgt_schar* val;
        if ((hash_ptr = strstr(TmpBuf, "(kh=")) == 0) return -55004;
        DgcBgmrList bl(TmpBuf, 1);
        if (EXCEPT) {
            DgcExcept* e = EXCEPTnC;
            PcaKeySvrSessionPool::logging(e->errCode(),
                                          "key infor compilation failed");
            delete e;
            return -55005;
        }
        DgcBgrammer* ki = bl.getNext();
        DgcBgrammer* kh = bl.getNext();
        if (ki == 0 || kh == 0) {
            PcaKeySvrSessionPool::logging("corrupted key infor:no ki or kh");
            return -55006;
        }
        if ((val = kh->getValue("kh")) == 0) {
            PcaKeySvrSessionPool::logging("corrupted key infor:no kh");
            return -55007;
        }
        memset(hash_buf, 0, 129);
        hash_buf_len = 128;
        PCI_initContext(&HashContext, 0, 256, PCI_CIPHER_SHA, 0, PCI_IVT_PIV1,
                        0, 1);
        if ((rtn = PCI_encrypt(&HashContext, (dgt_uint8*)TmpBuf,
                               (((dgt_uint64)hash_ptr) - ((dgt_uint64)TmpBuf)),
                               (dgt_uint8*)hash_buf, &hash_buf_len)) < 0) {
            if (HashContext.err_code)
                PcaKeySvrSessionPool::logging(HashContext.err_code,
                                              HashContext.err_msg);
            return rtn;
        }
        if (strncmp(val, hash_buf, hash_buf_len)) {
            PcaKeySvrSessionPool::logging("corrupted key infor");
            return -55008;
        }
        rtn = -55009;
        for (dgt_sint32 i = 0; i < 1; i++) {
            if ((val = ki->getValue("ki.enc_col_name")) == 0) break;
            rtn--;
            strncpy(EncColName, val, 128);
            if ((val = ki->getValue("ki.enc_col_id")) == 0) break;
            rtn--;
#ifdef WIN32
            EncColID = _strtoi64(val, 0, 10);
#else
            EncColID = dg_strtoll(val, 0, 10);
#endif
            if ((val = ki->getValue("ki.enc_col_id")) == 0) break;
            rtn--;
            if ((val = ki->getValue("ki.enc_length")) == 0) break;
            rtn--;
            KeyInfo.enc_length = (dgt_uint32)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.key_size")) == 0) break;
            rtn--;
            KeyInfo.key_size = (dgt_uint16)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.cipher_type")) == 0) break;
            rtn--;
            KeyInfo.cipher_type = (dgt_uint8)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.enc_mode")) == 0) break;
            rtn--;
            KeyInfo.enc_mode = (dgt_uint8)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.iv_type")) == 0) break;
            rtn--;
            KeyInfo.iv_type = (dgt_uint8)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.n2n_flag")) == 0) break;
            rtn--;
            KeyInfo.n2n_flag = (dgt_uint8)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.b64_txt_enc_flag")) == 0) break;
            rtn--;
            KeyInfo.b64_txt_enc_flag = (dgt_uint8)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.enc_start_pos")) == 0) break;
            rtn--;
            KeyInfo.enc_start_pos = (dgt_uint8)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.mask_char")) == 0) break;
            rtn--;
            strncpy(KeyInfo.mask_char, val, 32);
            if ((val = ki->getValue("ki.char_set")) == 0) break;
            rtn--;
            strncpy(KeyInfo.char_set, val, 32);
            if ((val = ki->getValue("ki.key")) == 0) break;
            rtn--;
            DgcBase64::decode2(val, strlen(val), KeyInfo.key, 64);
            if ((val = ki->getValue("ki.key_id")) == 0) break;
            rtn--;
#ifdef WIN32
            PrivInfo.key_id = _strtoi64(val, 0, 10);
#else
            PrivInfo.key_id = dg_strtoll(val, 0, 10);
#endif
            if ((val = ki->getValue("ki.key_id")) == 0) break;
            rtn--;
            if ((val = ki->getValue("ki.max_col_len")) == 0) break;
            rtn--;
            PrivInfo.max_col_len = (dgt_uint32)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.dec_alt_threshold")) == 0) break;
            rtn--;
            PrivInfo.dec_alt_threshold = (dgt_uint32)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.dec_masking_threshold")) == 0) break;
            rtn--;
            PrivInfo.dec_masking_threshold = (dgt_uint32)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.enc_priv")) == 0) break;
            rtn--;
            PrivInfo.enc_priv = (dgt_uint8)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.dec_priv")) == 0) break;
            rtn--;
            PrivInfo.dec_priv = (dgt_uint8)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.enc_no_priv_alert")) == 0) break;
            rtn--;
            PrivInfo.enc_no_priv_alert = (dgt_uint8)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.dec_no_priv_alert")) == 0) break;
            rtn--;
            PrivInfo.dec_no_priv_alert = (dgt_uint8)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.auth_fail_enc_priv")) == 0) break;
            rtn--;
            PrivInfo.auth_fail_enc_priv = (dgt_uint8)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.auth_fail_dec_priv")) == 0) break;
            rtn--;
            PrivInfo.auth_fail_dec_priv = (dgt_uint8)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.enc_audit_flag")) == 0) break;
            rtn--;
            PrivInfo.enc_audit_flag = (dgt_uint8)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.dec_audit_flag")) == 0) break;
            rtn--;
            PrivInfo.dec_audit_flag = (dgt_uint8)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.col_type")) == 0) break;
            rtn--;
            PrivInfo.col_type = (dgt_uint8)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.ophuek_flag")) == 0) break;
            rtn--;
            PrivInfo.ophuek_flag = (dgt_uint8)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.multibyte_flag")) == 0) break;
            rtn--;
            PrivInfo.multibyte_flag = (dgt_uint8)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.week_map")) == 0) break;
            rtn--;
            DgcBase64::decode2(val, strlen(val), PrivInfo.week_map, 12);

#if 1  // added by chchung 2017.8.9 for trailer importing
            if ((val = ki->getValue("ki.trailer_size")) == 0) break;
            rtn--;
            TrailerInfo.trailer_size = (dgt_uint8)strtol(val, 0, 10);
            if ((val = ki->getValue("ki.trailer_char")) == 0) break;
            DgcBase64::decode2(val, strlen(val),
                               (dgt_uint8*)TrailerInfo.trailer_char, 7);
#endif
            rtn = 0;
        }
        if (rtn)
            PcaKeySvrSessionPool::logging(rtn, "key infor parameter not found");
        return rtn;
    }
};

static const dgt_uint8 PCA_WEEKDAY_MASK_MAP[8] = {0x80, 0x40, 0x20, 0x10,
                                                  0x08, 0x04, 0x02, 0x01};

class PcaPrivilege : public PcaHashNode {
   private:
    dgt_sint64 EncColID;             // encryption column id
    dgt_sint64 VirtualKeyID;         // encryption virtual_key_id
    dgt_uint32 EffectiveTime;        // privilege effective time */
    dgt_uint32 MaxColLen;            // max column length
    dgt_uint32 DecAltThreshold;      // decrypt alert threshold
    dgt_uint32 DecMaskingThreshold;  // decrypt approve threshold
    dgt_uint8 ColType;               // column type
    dgt_uint8 MultiByteFlag;         // multibyte flag
    dgt_uint8 EncAuditFlag;          // encrypt audit flag
    dgt_uint8 DecAuditFlag;          // encrypt audit flag
    dgt_uint8 AuthFailEncPriv;
    dgt_uint8 AuthFailDecPriv;
    dgt_uint8 EncNoPrivAlert;
    dgt_uint8 DecNoPrivAlert;
    dgt_sint64 KeyID;                      // key id
    PcaKeyPool* KeyPool;                   // key pool
    PcaIVPool* IVPool;                     // iv pool
    pc_type_get_key_out* KeyInfo;          // key info
    pc_type_get_trailer_out* TrailerInfo;  // trailer info
    PCI_Context Context;                   // crypto context
    dgt_time PrivSetTime;  // the time when the privilege was set
    dgt_sint32 OphFlag;
    dgt_uint32 OphLen;

    dgt_uint8 EncPriv;  // 1:allow, 2:reject
    dgt_uint8 DecPriv;  // 1:allow, 2:masking, 3:encrypted data, 4:reject-error

    dgt_uint8 EncWeekMap[6];
    dgt_uint8 DecWeekMap[6];
    //
    // for logging
    //
    PcaPrivilege* UseList;
    dgt_sint64 EncCount;
    dgt_sint64 DecCount;
    dgt_sint64 AlertDecCount;
    dgt_sint64 MaskingDecCount;
    dgt_uint8 EncLogPrivFlag;
    dgt_uint8 DecLogPrivFlag;
    dgt_uint8 UseFlag;

    dgt_sint64 InsertEncCount;
    dgt_sint64 UpdateEncCount;
    dgt_sint64 DeleteEncCount;
    dgt_sint64 SelectEncCount;
    dgt_sint64 EtcEncCount;
    dgt_sint64 InsertDecCount;
    dgt_sint64 UpdateDecCount;
    dgt_sint64 DeleteDecCount;
    dgt_sint64 SelectDecCount;
    dgt_sint64 EtcDecCount;

#if 1  // added by chchung 2013.9.22 for adding test mode
    dgt_uint8 OpMode;
#endif
    // added by mwpark 2017.04.14 for ibk requirement
    // in case encrypting part data -> checking the mulitbyte char
    dgt_uint8 MultiByteSize;

    // adeed by mwpark 2017.06.17 for changing key periodically
    dgt_sint8 ChangeKeyFlag;
    PCI_Context CkContext;                   // Change Key Context
    pc_type_get_key_out* CkKeyInfo;          // key info
    pc_type_get_trailer_out* CkTrailerInfo;  // trailer info

    inline dgt_sint32 setContext() {
        if (KeyInfo == 0) {
            dgt_sint32 rtn;
            if ((rtn = KeyPool->getKeyInfo(KeyID, &KeyInfo, &TrailerInfo,
                                           &ChangeKeyFlag)))
                return rtn;
            if (ChangeKeyFlag == 1) {
                KeyInfo->b64_txt_enc_flag = 2;
            }
            if (ChangeKeyFlag == 2) {
                KeyInfo->b64_txt_enc_flag = 0;
            }
            if ((rtn = PCI_initContext(
                     &Context, KeyInfo->key, KeyInfo->key_size,
                     KeyInfo->cipher_type, KeyInfo->enc_mode, KeyInfo->iv_type,
                     KeyInfo->n2n_flag, KeyInfo->b64_txt_enc_flag,
                     KeyInfo->enc_start_pos, KeyInfo->enc_length, OphFlag,
                     TrailerInfo->trailer_size, TrailerInfo->trailer_char)))
                return rtn;
            if (KeyInfo->iv_type > PCI_IVT_PIV5) {  // get external iv
                pc_type_get_iv_out* iv_out;
                dgt_uint16 iv_size = 16;
                if (KeyInfo->cipher_type == PCI_CIPHER_SHA) {
                    iv_size = KeyInfo->key_size / 8;
                } else if (KeyInfo->cipher_type == PCI_CIPHER_TDES) {
                    iv_size = 8;
                } else {
                    iv_size = 16;
                }
                if ((rtn = IVPool->getIV(KeyInfo->iv_type, iv_size, &iv_out)))
                    return rtn;
                Context.cipher->setIV(iv_out->iv);
            }
            if (MultiByteFlag > 0 && !strcasecmp(KeyInfo->char_set, "UTF-8"))
                MultiByteSize = 3;
            if (MultiByteFlag > 0 && !strcasecmp(KeyInfo->char_set, "EUC-KR"))
                MultiByteSize = 2;
            if (MultiByteFlag > 0 && !strcasecmp(KeyInfo->char_set, "CP949"))
                MultiByteSize = 2;
            if (ChangeKeyFlag) {
                memset(&CkContext, 0, sizeof(PCI_Context));
                PCI_initContext(
                    &CkContext, KeyInfo->key, KeyInfo->key_size,
                    KeyInfo->cipher_type, KeyInfo->enc_mode, KeyInfo->iv_type,
                    KeyInfo->n2n_flag, KeyInfo->b64_txt_enc_flag,
                    KeyInfo->enc_start_pos, KeyInfo->enc_length, OphFlag,
                    TrailerInfo->trailer_size, TrailerInfo->trailer_char);
            }
        }
        return 0;
    };

    inline dgt_sint32 changeContext(dgt_uint8 key_id) {
        dgt_sint32 rtn;
        if ((rtn = KeyPool->getKeyInfo(key_id, &CkKeyInfo, &CkTrailerInfo,
                                       &ChangeKeyFlag)))
            return rtn;
        if ((rtn = PCI_changeContext(&CkContext, CkKeyInfo->key))) return rtn;
        return 0;
    }

   protected:
   public:
    static const dgt_sint32 PK_NO_ENCRYPT_PRIV = -30301;
    static const dgt_sint32 PK_NO_DECRYPT_PRIV = -30401;
    static const dgt_sint32 PK_NO_EXTERNAL_KEY = -30402;

    PcaPrivilege(dgt_sint64 enc_col_id, pc_type_get_priv_out* priv_out,
                 PcaKeyPool* key_pool, PcaIVPool* iv_pool,
                 dgt_uint8 multi_byte_size, dgt_sint64 virtual_key_id = 0)
        : EncColID(enc_col_id),
          VirtualKeyID(virtual_key_id),
          KeyID(priv_out->key_id),
          KeyPool(key_pool),
          IVPool(iv_pool),
          KeyInfo(0),
          OphFlag(0),
          OphLen(0),
          UseList(0) {
        AlertDecCount = 0;
        MaskingDecCount = 0;
#if 1  // added by chchung 2013.9.22 for adding test mode
        OpMode = 0;
#endif
        ChangeKeyFlag = 0;
        CkKeyInfo = 0;
        CkTrailerInfo = 0;

        setPrivilege(priv_out);
        setUseList();
        EncCount = 0;
        DecCount = 0;
        InsertEncCount = 0;
        UpdateEncCount = 0;
        DeleteEncCount = 0;
        SelectEncCount = 0;
        EtcEncCount = 0;
        InsertDecCount = 0;
        UpdateDecCount = 0;
        DeleteDecCount = 0;
        SelectDecCount = 0;
        EtcDecCount = 0;
        MultiByteSize = multi_byte_size;
    };

    virtual ~PcaPrivilege(){};

    inline dgt_sint64 encColID() { return EncColID; };
    inline dgt_sint64 getKeyId() { return KeyID; };
    inline dgt_sint64 virtualKeyID() { return VirtualKeyID; };
    inline dgt_schar* maskChar() { return KeyInfo->mask_char; };
    inline dgt_uint8 colType() { return ColType; };
    inline dgt_uint8 multiByteFlag() { return MultiByteFlag; };
    inline dgt_sint32 ophFlag() { return OphFlag; };

    inline dgt_schar* charSet(dgt_sint32* err_code) {
        if (KeyInfo == 0) {
            if ((*err_code = KeyPool->getKeyInfo(KeyID, &KeyInfo, &TrailerInfo,
                                                 &ChangeKeyFlag)))
                return 0;
            if (ChangeKeyFlag == 1) {
                KeyInfo->b64_txt_enc_flag = 2;
            }
            if (ChangeKeyFlag == 2) {
                KeyInfo->b64_txt_enc_flag = 0;
            }
            if ((*err_code = PCI_initContext(
                     &Context, KeyInfo->key, KeyInfo->key_size,
                     KeyInfo->cipher_type, KeyInfo->enc_mode, KeyInfo->iv_type,
                     KeyInfo->n2n_flag, KeyInfo->b64_txt_enc_flag,
                     KeyInfo->enc_start_pos, KeyInfo->enc_length, OphFlag,
                     TrailerInfo->trailer_size, TrailerInfo->trailer_char)))
                return 0;
            if (KeyInfo->iv_type > PCI_IVT_PIV5) {  // get external iv
                pc_type_get_iv_out* iv_out;
                dgt_uint16 iv_size = 16;
                if (KeyInfo->cipher_type == PCI_CIPHER_SHA) {
                    iv_size = KeyInfo->key_size / 8;
                } else if (KeyInfo->cipher_type == PCI_CIPHER_TDES) {
                    iv_size = 8;
                } else {
                    iv_size = 16;
                }
                if ((*err_code =
                         IVPool->getIV(KeyInfo->iv_type, iv_size, &iv_out)))
                    return 0;
                Context.cipher->setIV(iv_out->iv);
            }
            if (MultiByteFlag > 0 && !strcasecmp(KeyInfo->char_set, "UTF-8"))
                MultiByteSize = 3;
            if (MultiByteFlag > 0 && !strcasecmp(KeyInfo->char_set, "EUC-KR"))
                MultiByteSize = 2;
            if (MultiByteFlag > 0 && !strcasecmp(KeyInfo->char_set, "CP949"))
                MultiByteSize = 2;
            if (ChangeKeyFlag) {
                memset(&CkContext, 0, sizeof(PCI_Context));
                PCI_initContext(
                    &CkContext, KeyInfo->key, KeyInfo->key_size,
                    KeyInfo->cipher_type, KeyInfo->enc_mode, KeyInfo->iv_type,
                    KeyInfo->n2n_flag, KeyInfo->b64_txt_enc_flag,
                    KeyInfo->enc_start_pos, KeyInfo->enc_length, OphFlag,
                    TrailerInfo->trailer_size, TrailerInfo->trailer_char);
            }
        }
        return KeyInfo->char_set;
    };

    inline dgt_uint8 isDecryptAudit(dgt_sint32 sql_type = 0) {
        if (sql_type == 0)
            return DecAuditFlag;
        else if (sql_type == PCI_TYPE_INSERT)
            return DecAuditFlag & PCI_AUDIT_INSERT;
        else if (sql_type == PCI_TYPE_UPDATE)
            return DecAuditFlag & PCI_AUDIT_UPDATE;
        else if (sql_type == PCI_TYPE_DELETE)
            return DecAuditFlag & PCI_AUDIT_DELETE;
        else if (sql_type == PCI_TYPE_SELECT)
            return DecAuditFlag & PCI_AUDIT_SELECT;
        return DecAuditFlag & PCI_AUDIT_OTHERS;
    };

    inline dgt_uint8 isEncryptAudit(dgt_sint32 sql_type = 0) {
        if (sql_type == 0)
            return EncAuditFlag;
        else if (sql_type == PCI_TYPE_INSERT)
            return EncAuditFlag & PCI_AUDIT_INSERT;
        else if (sql_type == PCI_TYPE_UPDATE)
            return EncAuditFlag & PCI_AUDIT_UPDATE;
        else if (sql_type == PCI_TYPE_DELETE)
            return EncAuditFlag & PCI_AUDIT_DELETE;
        else if (sql_type == PCI_TYPE_SELECT)
            return EncAuditFlag & PCI_AUDIT_SELECT;
        return EncAuditFlag & PCI_AUDIT_OTHERS;
    };

    inline dgt_uint8 isDecryptAlert() { return DecNoPrivAlert; };
    inline dgt_uint8 isEncryptAlert() { return EncNoPrivAlert; };
    inline dgt_sint32 isAlert() {
        if (DecAltThreshold != 0 && AlertDecCount == DecAltThreshold) {
            AlertDecCount = 0;
            return 1;
        } else if (AlertDecCount == DecAltThreshold - 1) {
            //
            // for gettting Alert SqlStmt
            //
            return -1;
        }
        return 0;
    };
    inline dgt_sint32 isMasking() {
        if (DecMaskingThreshold != 0 && MaskingDecCount >= DecMaskingThreshold)
            return 1;
        return 0;
    };
    inline dgt_sint64 encCount() { return EncCount; };
    inline dgt_sint64 decCount() { return DecCount; };
    inline dgt_sint64 insertEncCount() { return InsertEncCount; };
    inline dgt_sint64 updateEncCount() { return UpdateEncCount; };
    inline dgt_sint64 deleteEncCount() { return DeleteEncCount; };
    inline dgt_sint64 selectEncCount() { return SelectEncCount; };
    inline dgt_sint64 etcEncCount() { return EtcEncCount; };
    inline dgt_sint64 insertDecCount() { return InsertDecCount; };
    inline dgt_sint64 updateDecCount() { return UpdateDecCount; };
    inline dgt_sint64 deleteDecCount() { return DeleteDecCount; };
    inline dgt_sint64 selectDecCount() { return SelectDecCount; };
    inline dgt_sint64 etcDecCount() { return EtcDecCount; };
    inline dgt_sint64 alertDecCount() { return DecAltThreshold; };
    inline dgt_sint64 maskingDecCount() { return MaskingDecCount; };
    inline dgt_sint64 maskingThreshold() { return DecMaskingThreshold; };
    inline dgt_void setEncLogPriv(dgt_uint8 flag) { EncLogPrivFlag = flag; };
    inline dgt_void setDecLogPriv(dgt_uint8 flag) { DecLogPrivFlag = flag; };
    inline dgt_uint8 encLogPrivFlag() { return EncLogPrivFlag; };
    inline dgt_uint8 decLogPrivFlag() { return DecLogPrivFlag; };
    inline dgt_uint8 useFlag() { return UseFlag; };
    inline dgt_uint8 setUseFlag(dgt_uint8 use_flag = 0) {
        return UseFlag = use_flag;
    };
    inline dgt_sint32 authFailEncPriv() { return AuthFailEncPriv; };
    inline dgt_sint32 authFailDecPriv() { return AuthFailDecPriv; };
    inline PcaPrivilege* useList() { return UseList; };
    inline dgt_uint8 encAuditFlag() { return EncAuditFlag; };
    inline dgt_uint8 decAuditFlag() { return DecAuditFlag; };
    inline dgt_void setEncCount(dgt_sint64 enc_count) { EncCount = enc_count; };
    inline dgt_void setDecCount(dgt_sint64 dec_count) { DecCount = dec_count; };
    inline dgt_void setInsertEncCount(dgt_sint64 enc_count) {
        InsertEncCount = enc_count;
    };
    inline dgt_void setUpdateEncCount(dgt_sint64 enc_count) {
        UpdateEncCount = enc_count;
    };
    inline dgt_void setDeleteEncCount(dgt_sint64 enc_count) {
        DeleteEncCount = enc_count;
    };
    inline dgt_void setSelectEncCount(dgt_sint64 enc_count) {
        SelectEncCount = enc_count;
    };
    inline dgt_void setEtcEncCount(dgt_sint64 enc_count) {
        EtcEncCount = enc_count;
    };
    inline dgt_void setInsertDecCount(dgt_sint64 enc_count) {
        InsertDecCount = enc_count;
    };
    inline dgt_void setUpdateDecCount(dgt_sint64 enc_count) {
        UpdateDecCount = enc_count;
    };
    inline dgt_void setDeleteDecCount(dgt_sint64 enc_count) {
        DeleteDecCount = enc_count;
    };
    inline dgt_void setSelectDecCount(dgt_sint64 enc_count) {
        SelectDecCount = enc_count;
    };
    inline dgt_void setEtcDecCount(dgt_sint64 enc_count) {
        EtcDecCount = enc_count;
    };

#if 1  // added by chchung 2013.9.22 for adding test mode
    inline dgt_uint8 opMode() { return OpMode; };
#endif

    inline dgt_void setUseList(PcaPrivilege* next = 0) {
        if (next == 0) {
            if (UseList) UseList->setUseList();
            EncCount = 0;
            DecCount = 0;
            EncLogPrivFlag = 1;
            DecLogPrivFlag = PCI_DEC_PRIV_DEC;
            UseFlag = 0;
            InsertEncCount = 0;
            UpdateEncCount = 0;
            DeleteEncCount = 0;
            SelectEncCount = 0;
            EtcEncCount = 0;
            InsertDecCount = 0;
            UpdateDecCount = 0;
            DeleteDecCount = 0;
            SelectDecCount = 0;
            EtcDecCount = 0;
        } else
            UseFlag = 1;
        UseList = next;
    };

    inline dgt_void privDump(dgt_schar* buf) {
        sprintf(
            buf,
            "EncColID[%lld] EffectiveTime[%u] MaxColLen[%u] AltThreshold[%u] "
            "maskingThreshold[%u] ColType[%d] Multibyte[%d] \n"
            "EncPriv[%d] DecPriv[%d] AuthFailEncPriv[%d] AuthFailDecPriv[%d] "
            "EncNoPrivAlert[%d] DecNoPrivAlert[%d]\n",
            EncColID, EffectiveTime, MaxColLen, DecAltThreshold,
            DecMaskingThreshold, ColType, MultiByteFlag, EncPriv, DecPriv,
            AuthFailEncPriv, AuthFailDecPriv, EncNoPrivAlert, DecNoPrivAlert);
    }

    inline dgt_void setPrivilege(pc_type_get_priv_out* priv_out) {
        //
        // translate privilege bit map into detail privilege array.
        // -----------------------------------------------------------------------------------------
        // bit map : global priv[8 bits] + detail privilege set[32 bits] * 12
        // -----------------------------------------------------------------------------------------
        // detail privilege set : week day map[8 bits] + start hour[5 bits] +
        // start minute[6 bits] +
        //                        end hour[5 bits] + end minute[6 bits] + priv[2
        //                        bits]
        // -----------------------------------------------------------------------------------------
        //

        // Effective Time = petra_cipher_api.conf(rule_effective_time)
        EffectiveTime = PcaKeySvrSessionPool::ruleEffectiveTime();
        MaxColLen = priv_out->max_col_len;
        DecAltThreshold = priv_out->dec_alt_threshold;
        DecMaskingThreshold = priv_out->dec_masking_threshold;
        ColType = priv_out->col_type;
        MultiByteFlag = priv_out->multibyte_flag;
#if 1  // modified by chchung 2013.9.22 for adding test mode
        OpMode = priv_out->ophuek_flag & 0x02;
        OphFlag = priv_out->ophuek_flag & 0x01;
#else
        OphFlag = priv_out->ophuek_flag;
#endif
        if (OphFlag) OphLen = ophLength();

#if 0
		if ((EncPriv & PCI_ENCRYPT_PRIV) != (priv_out->enc_priv & PCI_ENCRYPT_PRIV)) {
			//
			// set encrypt log privilege
			//
			EncLogPrivFlag = (priv_out->enc_priv & PCI_ENCRYPT_PRIV);
		}
		if ((DecPriv & PCI_DECRYPT_PRIV_MASK) != (priv_out->dec_priv & PCI_DECRYPT_PRIV_MASK)) {
			//
			// set decrypt log privilege
			//
			DecLogPrivFlag = (priv_out->dec_priv[0] & PCI_DECRYPT_PRIV_MASK);
		}
#else
        // set encrypt log privilege
        // enc_priv: 1:allow,2:reject
        EncPriv = priv_out->enc_priv;
        EncLogPrivFlag = priv_out->enc_priv;
        // set decrypt log privilege
        // dec_priv: 1:allow,2:masking,3:encrypted data,4:reject-error
        DecPriv = priv_out->dec_priv;
        DecLogPrivFlag = priv_out->dec_priv;
#endif

        EncNoPrivAlert = priv_out->enc_no_priv_alert;
        DecNoPrivAlert = priv_out->dec_no_priv_alert;
        AuthFailEncPriv = priv_out->auth_fail_enc_priv;
        AuthFailDecPriv = priv_out->auth_fail_dec_priv;
        EncAuditFlag = priv_out->enc_audit_flag;
        DecAuditFlag = priv_out->dec_audit_flag;
        PrivSetTime = dgtime(&PrivSetTime);
        //
        // week_map[0]:day bitmap , week_map[1]:start_hour,
        // week_map[2]:start_min week_map[3]:end_hour, week_map[4]:end_min,
        // week_map[5]:contrary flag
        EncWeekMap[0] = priv_out->week_map[0];
        EncWeekMap[1] = priv_out->week_map[1];
        EncWeekMap[2] = priv_out->week_map[2];
        EncWeekMap[3] = priv_out->week_map[3];
        EncWeekMap[4] = priv_out->week_map[4];
        EncWeekMap[5] = priv_out->week_map[5];
        DecWeekMap[0] = priv_out->week_map[6];
        DecWeekMap[1] = priv_out->week_map[7];
        DecWeekMap[2] = priv_out->week_map[8];
        DecWeekMap[3] = priv_out->week_map[9];
        DecWeekMap[4] = priv_out->week_map[10];
        DecWeekMap[5] = priv_out->week_map[11];
    };

    inline dgt_sint32 isPrivEffective() {
        if (EffectiveTime == 0) return 1;
        dgt_time ct = dgtime(&ct);
        if ((ct - PrivSetTime) <= EffectiveTime) return 1;
        return 0;
    };

    inline dgt_uint8 getCryptPriv(dgt_uint8 op_type, dgt_sint32 sql_type = 0) {
        if (op_type == PCI_CRYPT_OP_ENCRYPT) {
            if (EncWeekMap[0] > 0) {
                dgt_time ct = dgtime(&ct);
                time_t temp_ct = ct;
                struct tm res;
                struct tm* now = localtime_r(&temp_ct, &res);
                dgt_sint8 yes_flag = 0;
                for (;;) {
                    if (EncWeekMap[0] & PCA_WEEKDAY_MASK_MAP[now->tm_wday]) {
                        if (now->tm_hour < EncWeekMap[1] ||
                            (now->tm_hour == EncWeekMap[1] &&
                             now->tm_min < EncWeekMap[2]))
                            break;
                        if ((EncWeekMap[3] && now->tm_hour > EncWeekMap[3]) ||
                            (now->tm_hour == EncWeekMap[3] &&
                             now->tm_min > EncWeekMap[4]))
                            break;
                        yes_flag = 1;
                    }
                    break;
                }
                if ((yes_flag && !EncWeekMap[5]) ||
                    (!yes_flag && EncWeekMap[5])) {
                    EncCount++;
                    if (sql_type) {
                        if (sql_type == 1)
                            InsertEncCount++;
                        else if (sql_type == 2)
                            UpdateEncCount++;
                        else if (sql_type == 3)
                            DeleteEncCount++;
                        else if (sql_type == 4)
                            SelectEncCount++;
                        else
                            EtcEncCount++;
                    }
                    return EncPriv;
                } else {
                    //
                    // not included time range (default = allow encryption)
                    //
                    EncCount++;
                    if (sql_type) {
                        if (sql_type == 1)
                            InsertEncCount++;
                        else if (sql_type == 2)
                            UpdateEncCount++;
                        else if (sql_type == 3)
                            DeleteEncCount++;
                        else if (sql_type == 4)
                            SelectEncCount++;
                        else
                            EtcEncCount++;
                    }
                    return PCI_ENCRYPT_PRIV;
                }
            } else {
                EncCount++;
                if (sql_type) {
                    if (sql_type == 1)
                        InsertEncCount++;
                    else if (sql_type == 2)
                        UpdateEncCount++;
                    else if (sql_type == 3)
                        DeleteEncCount++;
                    else if (sql_type == 4)
                        SelectEncCount++;
                    else
                        EtcEncCount++;
                }
                return EncPriv;
            }
        } else {
            if (DecWeekMap[0] > 0) {
                dgt_time ct = dgtime(&ct);
                time_t temp_ct = ct;
                struct tm res;
                struct tm* now = localtime_r(&temp_ct, &res);
                dgt_sint8 yes_flag = 0;
                for (;;) {
                    if (DecWeekMap[0] & PCA_WEEKDAY_MASK_MAP[now->tm_wday]) {
                        if (now->tm_hour < DecWeekMap[1] ||
                            (now->tm_hour == DecWeekMap[1] &&
                             now->tm_min < DecWeekMap[2]))
                            break;
                        if ((DecWeekMap[3] && now->tm_hour > DecWeekMap[3]) ||
                            (now->tm_hour == DecWeekMap[3] &&
                             now->tm_min > DecWeekMap[4]))
                            break;
                        yes_flag = 1;
                    }
                    break;
                }
                if ((yes_flag && !DecWeekMap[5]) ||
                    (!yes_flag && DecWeekMap[5])) {
                    DecCount++;
                    AlertDecCount++;
                    if (MaskingDecCount <= DecMaskingThreshold)
                        MaskingDecCount++;
                    if (sql_type) {
                        if (sql_type == 1)
                            InsertDecCount++;
                        else if (sql_type == 2)
                            UpdateDecCount++;
                        else if (sql_type == 3)
                            DeleteDecCount++;
                        else if (sql_type == 4)
                            SelectDecCount++;
                        else
                            EtcDecCount++;
                    }
                    return DecPriv;
                } else {
                    //
                    // not included time range (default = allow encryption)
                    //
                    DecCount++;
                    AlertDecCount++;
                    if (MaskingDecCount <= DecMaskingThreshold)
                        MaskingDecCount++;
                    if (sql_type) {
                        if (sql_type == 1)
                            InsertDecCount++;
                        else if (sql_type == 2)
                            UpdateDecCount++;
                        else if (sql_type == 3)
                            DeleteDecCount++;
                        else if (sql_type == 4)
                            SelectDecCount++;
                        else
                            EtcDecCount++;
                    }
                    return PCI_DEC_PRIV_DEC;
                }
            } else {
                DecCount++;
                AlertDecCount++;
                if (MaskingDecCount <= DecMaskingThreshold) MaskingDecCount++;
                if (sql_type) {
                    if (sql_type == 1)
                        InsertDecCount++;
                    else if (sql_type == 2)
                        UpdateDecCount++;
                    else if (sql_type == 3)
                        DeleteDecCount++;
                    else if (sql_type == 4)
                        SelectDecCount++;
                    else
                        EtcDecCount++;
                }
                return DecPriv;
            }
        }
        return 1;
    };

    inline dgt_uint32 maxColLength() { return MaxColLen; };

    inline dgt_uint8 encStartPos(dgt_uint32 src_len) {
        if (KeyInfo) {
            if (KeyInfo->enc_start_pos == 0 && KeyInfo->enc_length > 0) {
                dgt_uint8 enc_start_pos = KeyInfo->enc_start_pos;
                if (src_len <= (dgt_uint32)KeyInfo->enc_length)
                    enc_start_pos = 1;
                else
                    enc_start_pos = src_len - (KeyInfo->enc_length) + 1;
                return enc_start_pos;
            } else {
                return KeyInfo->enc_start_pos;
            }
        }
        return 0;
    };

    inline dgt_uint32 maskingLength(dgt_uint32 src_len) {
        if (KeyInfo && src_len >= KeyInfo->enc_start_pos) {
            dgt_uint32 enc_target_len = src_len - KeyInfo->enc_start_pos + 1;
            if (KeyInfo->enc_length && KeyInfo->enc_length < enc_target_len)
                return KeyInfo->enc_length;
            return enc_target_len;
        }
        return 0;
    };

    inline dgt_uint32 encryptLength(dgt_sint32 src_len) {
        dgt_sint32 rtn;
        if ((rtn = setContext())) return rtn;
        dgt_uint32 length = PCI_encryptLength(&Context, src_len);
        if (ChangeKeyFlag == 1) length += 4;
        return length;
    };

    inline dgt_sint32 ophLength() {
        dgt_sint32 src_len = MaxColLen;
        if (MultiByteFlag) src_len *= 3;
        return PCI_ophuekLength(src_len, ColType, 1);
    };

    inline dgt_sint32 encrypt(dgt_uint8* src, dgt_sint32 src_len,
                              dgt_uint8* dst, dgt_uint32* dst_len,
                              dgt_uint8 double_enc_check = 0,
                              dgt_uint8 init_encrypt_flag = 0,
                              dgt_uint8* set_key = 0, dgt_uint8* set_iv = 0,
                              dgt_uint8 pad_type = 0) {
        dgt_sint32 rtn;
        if ((rtn = setContext())) return rtn;

#if 1  // added by chchung 2013.9.13 for adding test mode
        if (init_encrypt_flag == 0 && KeyPool->opMode() >= PCI_OP_NO_CRYPT)
            return 0;
#endif
        Context.double_enc_check = double_enc_check;
        //
        // if coltype == char then trim
        //
#if 1
        if (ColType == PCI_SRC_TYPE_CHAR) {
            dgt_sint32 trim_byte = 0;
            dgt_sint32 i = 0;
            for (i = src_len - 1; i >= 0; i--) {
                if (src[i] == ' ' || src[i] == '\0') {
                    src[i] = '\0';
                    trim_byte++;
                } else {
                    break;
                }
            }
            src_len -= trim_byte;
            // added by mwpark 2017.09.27 for ibk requirement
            // if src data is padded all spaces
            // replace one byte space
            if (src_len == 0 && trim_byte > 0) {
                src_len = 1;
                src[0] = ' ';
            }
            if (PcaKeySvrSessionPool::vlColID() > 0) {
                // added by mwpark 2017.09.27 for ibk requirement
                // if src data is XXXXXXXXXX
                // return src data
                if (src_len == 10) {
                    dgt_sint32 is_match = 1;
                    dgt_sint32 i = 0;
                    for (i = 0; i < 10; i++) {
                        if (src[i] != 'X') is_match = 0;
                    }
                    if (is_match) {
                        memcpy(dst, src, src_len);
                        *dst_len = src_len;
                        return 0;
                    }
                }
            }
        } else {
            if (PcaKeySvrSessionPool::vlColID() > 0) {
                // added by mwpark 2017.09.27 for ibk requirement
                // if src data is XXXXXXXXXX
                // return src data
                if (src_len == 10) {
                    dgt_sint32 is_match = 1;
                    dgt_sint32 i = 0;
                    for (i = 0; i < 10; i++) {
                        if (src[i] != 'X') is_match = 0;
                    }
                    if (is_match) {
                        memcpy(dst, src, src_len);
                        *dst_len = src_len;
                        return 0;
                    }
                }
            }
        }
#endif

        // modified by mwpark 2016.06.09 for nh requirement (set key, set iv)
        if (set_key && *set_key) {
            if (pad_type) Context.pad_type = pad_type;
            Context.cipher->initialize(set_key, Context.key_size,
                                       Context.enc_mode, Context.pad_type);
        }
        if (set_iv && *set_iv) {
            Context.cipher->setIV(set_iv);
        }

        dgt_uint8 enc_start_pos = 0;
        dgt_uint32 enc_length = 0;
        if (PcaKeySvrSessionPool::vlColID() == KeyID) {
            if (src_len < PcaKeySvrSessionPool::vlLength()) {
                enc_start_pos = Context.enc_start_pos;
                enc_length = Context.enc_length;
                Context.enc_start_pos = 1;
                Context.enc_length = 0;
            } else if (src_len == PcaKeySvrSessionPool::vlEncLength() &&
                       Context.double_enc_check) {
                dgt_sint32 is_match = 0;
                is_match = PCI_checkCRC32(src, src_len);
                if (is_match) {
                    dgt_sint32 rtn = decrypt(src, src_len, dst, dst_len);
                    if (rtn < 0) {
                        Context.err_code = 0;
                    } else {
                        memcpy(dst, src, src_len);
                        *dst_len = src_len;
                        Context.err_code = 0;
                        return 0;
                    }
                }
            }
        }

        // multibyte check
        if (Context.enc_start_pos != 1 &&
            src[Context.enc_start_pos - 2] > 127) {
            dgt_sint32 i = 0;
            dgt_sint32 multi_byte_cnt = 0;
            for (i = 0; i < Context.enc_start_pos - 1; i++) {
                if (src[i] > 127) multi_byte_cnt++;
            }
            if (multi_byte_cnt > 0) {
                enc_start_pos = Context.enc_start_pos;
                dgt_sint32 remains =
                    MultiByteSize - (multi_byte_cnt % MultiByteSize);
                if (remains == 1) Context.enc_start_pos++;
            }
        }

        if (OphFlag && src_len <= 165) {
            // output data = ophuek data + encrypted data
            // dgt_uint32 ophDstLen=MaxColLen+1;
            // opheuk index = src_len less than 128 bytes
            dgt_uint32 ophDstLen = (dgt_uint8)src_len + 1;
            dgt_uint32 encDstLen = *dst_len;
            PCI_OPHUEK(&Context, src, src_len, dst, &ophDstLen, EncColID,
                       ColType, 0, 1);
            PCI_encrypt(&Context, src, src_len, dst + ophDstLen, &encDstLen,
                        (dgt_uint8)ophDstLen);
            *dst_len = ophDstLen + encDstLen;
        } else {
            if (ChangeKeyFlag == 1) {
                PCI_encrypt(&Context, src, src_len, dst, dst_len, 0);
                dgt_uint8 trailer[3] = {0, 0, 0};
                trailer[0] = (dgt_uint8)KeyID;
                dgt_schar data[4];
                memset(data, 0, 4);
                DgcBase64::encode(trailer, 3, (dgt_schar*)data, 4);
                memcpy(dst + *dst_len, data, 4);
                *dst_len += 4;
            } else if (ChangeKeyFlag == 2) {
                PCI_encrypt(&Context, src, src_len, dst, dst_len, 0);
                dst[*dst_len - 1] = (dgt_uint8)KeyID;
            } else {
                PCI_encrypt(&Context, src, src_len, dst, dst_len, 0);
            }
        }
        if (Context.err_code && Context.double_enc_check == 0)
            PcaKeySvrSessionPool::logging(Context.err_code, Context.err_msg);
        if (PcaKeySvrSessionPool::vlColID() == KeyID) {
            if (src_len < PcaKeySvrSessionPool::vlLength()) {
                Context.enc_start_pos = enc_start_pos;
                Context.enc_length = enc_length;
            }
        }
        if (enc_start_pos > 0) Context.enc_start_pos = enc_start_pos;

        return Context.err_code;
    };

    inline dgt_sint32 decrypt(dgt_uint8* src, dgt_sint32 src_len,
                              dgt_uint8* dst, dgt_uint32* dst_len,
                              dgt_uint8* set_key = 0, dgt_uint8* set_iv = 0,
                              dgt_uint8 dec_fail_rtn_src = 0,
                              dgt_uint8 pad_type = 0) {
        dgt_sint32 rtn;
        if ((rtn = setContext())) return rtn;

#if 1  // added by chchung 2013.9.13 for adding test mode
        if (KeyPool->opMode() >= PCI_OP_NO_CRYPT) return 0;
#endif
            //
            // if coltype == char then trim
            //
#if 1
        if (ColType == PCI_SRC_TYPE_CHAR) {
            dgt_sint32 trim_byte = 0;
            dgt_sint32 i = 0;
            for (i = src_len - 1; i >= 0; i--) {
                if (src[i] == ' ' || src[i] == '\0') {
                    src[i] = '\0';
                    trim_byte++;
                } else {
                    break;
                }
            }
            src_len -= trim_byte;
            // added by mwpark 2017.09.27 for ibk requirement
            // if src data is XXXXXXXXXX
            // return src data
            if (PcaKeySvrSessionPool::vlColID() > 0) {
                if (src_len == 10) {
                    dgt_sint32 is_match = 1;
                    dgt_sint32 i = 0;
                    for (i = 0; i < 10; i++) {
                        if (src[i] != 'X') is_match = 0;
                    }
                    if (is_match) {
                        memcpy(dst, src, src_len);
                        *dst_len = src_len;
                        return 0;
                    }
                }
            }
        } else {
            if (PcaKeySvrSessionPool::vlColID() > 0) {
                // added by mwpark 2017.09.27 for ibk requirement
                // if src data is XXXXXXXXXX
                // return src data
                if (src_len == 10) {
                    dgt_sint32 is_match = 1;
                    dgt_sint32 i = 0;
                    for (i = 0; i < 10; i++) {
                        if (src[i] != 'X') is_match = 0;
                    }
                    if (is_match) {
                        memcpy(dst, src, src_len);
                        *dst_len = src_len;
                        return 0;
                    }
                }
            }
        }
#endif

        // modified by mwpark 2016.06.09 for nh requirement (set key, set iv)
        if (set_key && *set_key) {
            if (pad_type) Context.pad_type = pad_type;
            Context.cipher->initialize(set_key, Context.key_size,
                                       Context.enc_mode, Context.pad_type);
        }
        if (set_iv && *set_iv) {
            Context.cipher->setIV(set_iv);
        }

        dgt_uint8 enc_start_pos = 0;
        dgt_uint32 enc_length = 0;
        if (PcaKeySvrSessionPool::vlColID() == KeyID) {
            if (src_len == PcaKeySvrSessionPool::vlEncLength()) {
                enc_start_pos = Context.enc_start_pos;
                enc_length = Context.enc_length;
                Context.enc_start_pos = 1;
                Context.enc_length = 0;
            }
        }

        // multibyte check
        if (Context.enc_start_pos != 1 &&
            src[Context.enc_start_pos - 2] > 127) {
            dgt_sint32 i = 0;
            dgt_sint32 multi_byte_cnt = 0;
            for (i = 0; i < Context.enc_start_pos - 1; i++) {
                if (src[i] > 127) multi_byte_cnt++;
            }
            if (multi_byte_cnt > 0) {
                enc_start_pos = Context.enc_start_pos;
                dgt_sint32 remains =
                    MultiByteSize - (multi_byte_cnt % MultiByteSize);
                if (remains == 1) Context.enc_start_pos++;
            }
        }

        if (OphFlag && src_len > 0) {
            // parse the trailer (trailer[2] = oph end position)
            dgt_uint8* b64_tailer =
                src + src_len - 4;  // 4 = PCC_ENC_TRAILER_LENGTH;
            dgt_uint8 trailer[3] = {0, 0, 0};
            DgcBase64::decode((dgt_schar*)b64_tailer, 4, trailer, 3);
            if (trailer[2]) {
                dgt_uint8 ophlen = trailer[2];
                src_len = src_len - ophlen;
                PCI_decrypt(&Context, src + ophlen, src_len, dst, dst_len);
            } else {
                PCI_decrypt(&Context, src, src_len, dst, dst_len);
            }
        } else {
            if (ChangeKeyFlag == 1) {
                dgt_uint8* b64_tailer = src + src_len - 4;
                dgt_uint8 trailer[3] = {0, 0, 0};
                DgcBase64::decode((dgt_schar*)b64_tailer, 4, trailer, 3);
                dgt_uint8 key_id = trailer[0];
                dgt_sint32 rtn = 0;
                if (KeyID != key_id) {
                    if ((rtn = changeContext(key_id))) return rtn;
                    PCI_decrypt(&CkContext, src, src_len - 4, dst, dst_len);
                } else {
                    PCI_decrypt(&Context, src, src_len - 4, dst, dst_len);
                }
            } else if (ChangeKeyFlag == 2) {
                dgt_uint8 key_id = src[src_len - 1];
                dgt_sint32 rtn = 0;
                if (KeyID != key_id) {
                    if ((rtn = changeContext(key_id))) return rtn;
                    PCI_decrypt(&CkContext, src, src_len, dst, dst_len);
                } else {
                    PCI_decrypt(&Context, src, src_len, dst, dst_len);
                }
            } else {
                PCI_decrypt(&Context, src, src_len, dst, dst_len);
            }
        }
        if (Context.err_code && dec_fail_rtn_src == 0)
            PcaKeySvrSessionPool::logging(Context.err_code, Context.err_msg);
        if (PcaKeySvrSessionPool::vlColID() == KeyID) {
            if (src_len == PcaKeySvrSessionPool::vlEncLength()) {
                Context.enc_start_pos = enc_start_pos;
                Context.enc_length = enc_length;
            }
        }
        if (enc_start_pos > 0) Context.enc_start_pos = enc_start_pos;
        if (Context.err_code && dec_fail_rtn_src == 1) {
            *dst_len = src_len;
        }
        return Context.err_code;
    };

    inline dgt_sint32 OPHUEK(dgt_uint8* src, dgt_sint32 src_len, dgt_uint8* dst,
                             dgt_uint32* dst_len, dgt_sint32 src_enc_flag) {
        dgt_sint32 rtn;
        if ((rtn = setContext())) return rtn;

        if (src_enc_flag) {
            dgt_sint32 rtn = decrypt(src, src_len, dst, dst_len);
            if (rtn < 0) return rtn;
            memcpy(src, dst, *dst_len);
            src_len = *dst_len;
        }
        dgt_uint32 ophDstLen = (dgt_uint8)src_len + 1;
        PCI_OPHUEK(&Context, src, src_len, dst, &ophDstLen, EncColID, ColType,
                   0, 1);
        *dst_len = ophDstLen;
        if (Context.err_code)
            PcaKeySvrSessionPool::logging(Context.err_code, Context.err_msg);
        return Context.err_code;
    };

    inline dgt_sint32 getKey(dgt_uint8* key_buffer, dgt_sint32* key_len) {
        dgt_sint32 rtn;
        if ((rtn = setContext())) return rtn;
        if (KeyInfo->cipher_type == PCI_CIPHER_TRANSFER) {
            *key_len = KeyInfo->key_size / 8;
            memcpy(key_buffer, KeyInfo->key, *key_len);
        } else {
            Context.err_code = PK_NO_EXTERNAL_KEY;
            sprintf(Context.err_msg, "no external key");
        }
        if (Context.err_code)
            PcaKeySvrSessionPool::logging(Context.err_code, Context.err_msg);
        return Context.err_code;
    };

    inline dgt_sint32 getKeyInfo(PcaPrivCompiler& priv_compiler) {
        dgt_sint32 rtn;
        if ((rtn = setContext())) return rtn;
        memcpy(priv_compiler.keyInfo(), KeyInfo, sizeof(pc_type_get_key_out));
        memcpy(priv_compiler.trailerInfo(), TrailerInfo,
               sizeof(pc_type_get_trailer_out));
        pc_type_get_priv_out* po = priv_compiler.privInfo();

        po->key_id = KeyID;
        po->max_col_len = MaxColLen;
        po->dec_alt_threshold = DecAltThreshold;
        po->dec_masking_threshold = DecMaskingThreshold;
        po->enc_priv = EncPriv;
        po->dec_priv = DecPriv;
        po->enc_no_priv_alert = EncNoPrivAlert;
        po->dec_no_priv_alert = DecNoPrivAlert;
        po->auth_fail_enc_priv = AuthFailEncPriv;
        po->auth_fail_dec_priv = AuthFailDecPriv;
        po->enc_audit_flag = EncAuditFlag;
        po->dec_audit_flag = DecAuditFlag;
        po->col_type = ColType;
        po->ophuek_flag = OpMode | OphFlag;
        po->multibyte_flag = MultiByteFlag;
        memcpy(po->week_map, EncWeekMap, 6);
        memcpy(po->week_map + 6, DecWeekMap, 6);
        return 0;
    }
};

class PcaPrivilegePool : public DgcObject {
   private:
    static const dgt_sint32 PPP_PRIV_HASH_MAX = 100;
    static const dgt_sint32 PPP_ERR_LOCK_FAIL = -30309;

    dgt_slock PoolLatch;
    PcaPrivilege* PrivHashTable[PPP_PRIV_HASH_MAX];
    PcaPrivilege* UseList;
    PcaPrivilege* CurrUsePriv;

    inline dgt_void registerUseList(PcaPrivilege* priv) {
        if (priv && priv->useFlag() == 0) {
            if (UseList == 0) {
                priv->setUseFlag(1);
                CurrUsePriv = UseList = priv;
            } else {
                priv->setUseList(UseList);
                CurrUsePriv = UseList = priv;
            }
        }
    };

    inline dgt_void clearUseList() {
        if (!DgcSpinLock::lock(&PoolLatch)) {
            if (UseList) {
                UseList->setUseList();
                UseList = 0;
            }
            CurrUsePriv = 0;
            DgcSpinLock::unlock(&PoolLatch);
        }
    };

   protected:
   public:
    PcaPrivilegePool() : UseList(0), CurrUsePriv(0) {
        DgcSpinLock::unlock(&PoolLatch);
        for (dgt_sint32 i = 0; i < PPP_PRIV_HASH_MAX; i++) PrivHashTable[i] = 0;
    };

    virtual ~PcaPrivilegePool() {
        for (dgt_sint32 i = 0; i < PPP_PRIV_HASH_MAX; i++)
            delete PrivHashTable[i];
    };

    inline dgt_void reset() {
        for (dgt_sint32 i = 0; i < PPP_PRIV_HASH_MAX; i++) {
            delete PrivHashTable[i];
            PrivHashTable[i] = 0;
        }
        CurrUsePriv = UseList = 0;
    };

    inline dgt_sint32 getPriv(dgt_sint64 enc_col_id, PcaPrivilege** rtn_priv) {
        dgt_sint64 hval = enc_col_id % PPP_PRIV_HASH_MAX;
        PcaPrivilege* priv = 0;
        if (DgcSpinLock::lock(&PoolLatch)) {
            return PPP_ERR_LOCK_FAIL;
        } else {
            PcaPrivilege* priv = PrivHashTable[hval];
            while (priv) {
                if (priv->encColID() == enc_col_id) {
                    *rtn_priv = priv;
                    registerUseList(priv);
                    break;
                }
                priv = (PcaPrivilege*)priv->next();
            }
            DgcSpinLock::unlock(&PoolLatch);
        }
        return 0;
    };

    inline dgt_sint32 putPriv(PcaPrivilege* priv, PcaPrivilege** rtn_priv) {
        if (priv) {
            dgt_sint64 hval = priv->encColID() % PPP_PRIV_HASH_MAX;
            if (DgcSpinLock::lock(&PoolLatch)) {
                delete priv;
                return PPP_ERR_LOCK_FAIL;
            } else {
                PcaPrivilege* tmp_priv = PrivHashTable[hval];
                while (tmp_priv) {
                    if (tmp_priv->encColID() == priv->encColID()) break;
                    tmp_priv = (PcaPrivilege*)tmp_priv->next();
                }
                if (tmp_priv == 0) {
                    if (PrivHashTable[hval]) priv->setNext(PrivHashTable[hval]);
                    PrivHashTable[hval] = priv;
                }
                if (tmp_priv) {
                    //
                    // already exists
                    //
                    delete priv;
                    *rtn_priv = tmp_priv;
                } else {
                    *rtn_priv = priv;
                    if (PcaKeySvrSessionPool::traceLevel() > 2)
                        PcaKeySvrSessionPool::logging(
                            "new privilege[%lld] added", priv->encColID());
                }
                registerUseList(*rtn_priv);
                DgcSpinLock::unlock(&PoolLatch);
            }
        }
        return 0;
    };

    inline dgt_sint32 getVKeyPriv(dgt_sint64 virtual_key_id,
                                  PcaPrivilege** rtn_priv) {
        dgt_sint64 hval = virtual_key_id % PPP_PRIV_HASH_MAX;
        PcaPrivilege* priv = 0;
        if (DgcSpinLock::lock(&PoolLatch)) {
            return PPP_ERR_LOCK_FAIL;
        } else {
            PcaPrivilege* priv = PrivHashTable[hval];
            while (priv) {
                if (priv->virtualKeyID() == virtual_key_id) {
                    *rtn_priv = priv;
                    registerUseList(priv);
                    break;
                }
                priv = (PcaPrivilege*)priv->next();
            }
            DgcSpinLock::unlock(&PoolLatch);
        }
        return 0;
    };

    inline dgt_sint32 putVKeyPriv(PcaPrivilege* priv, PcaPrivilege** rtn_priv) {
        if (priv) {
            dgt_sint64 hval = priv->virtualKeyID() % PPP_PRIV_HASH_MAX;
            if (DgcSpinLock::lock(&PoolLatch)) {
                delete priv;
                return PPP_ERR_LOCK_FAIL;
            } else {
                PcaPrivilege* tmp_priv = PrivHashTable[hval];
                while (tmp_priv) {
                    if (tmp_priv->virtualKeyID() == priv->virtualKeyID()) break;
                    tmp_priv = (PcaPrivilege*)tmp_priv->next();
                }
                if (tmp_priv == 0) {
                    if (PrivHashTable[hval]) priv->setNext(PrivHashTable[hval]);
                    PrivHashTable[hval] = priv;
                }
                if (tmp_priv) {
                    //
                    // already exists
                    //
                    delete priv;
                    *rtn_priv = tmp_priv;
                } else {
                    *rtn_priv = priv;
                    if (PcaKeySvrSessionPool::traceLevel() > 2)
                        PcaKeySvrSessionPool::logging(
                            "new vkey privilege[%lld] added",
                            priv->virtualKeyID());
                }
                registerUseList(*rtn_priv);
                DgcSpinLock::unlock(&PoolLatch);
            }
        }
        return 0;
    };

    inline dgt_sint32 setLogRequest(pc_type_log_request_in* log_request) {
        if (log_request->stmt_id == 128) {
            // for nong hyup api logging
            while (CurrUsePriv) {
                // PcaKeySvrSessionPool::logging("[%lld][%lld][%lld][%lld][%lld][%lld][%lld][%lld][%lld]\n",CurrUsePriv->encColID(),CurrUsePriv->insertEncCount(),CurrUsePriv->updateEncCount(),CurrUsePriv->deleteEncCount(),CurrUsePriv->selectEncCount(),CurrUsePriv->insertDecCount(),CurrUsePriv->updateDecCount(),CurrUsePriv->deleteDecCount(),CurrUsePriv->selectDecCount());
                // insert, update, delete, select sequence
                log_request->enc_count = 0;
                log_request->dec_count = 0;
                if (CurrUsePriv->insertEncCount() &&
                    CurrUsePriv->isEncryptAudit(1)) {
                    log_request->enc_col_id = CurrUsePriv->encColID();
                    log_request->enc_count = CurrUsePriv->insertEncCount();
                    log_request->enc_no_priv_flag =
                        CurrUsePriv->encLogPrivFlag();
                    log_request->sql_type = 1;
                    CurrUsePriv->setInsertEncCount(0);
                    return 1;
                } else if (CurrUsePriv->updateEncCount() &&
                           CurrUsePriv->isEncryptAudit(2)) {
                    log_request->enc_col_id = CurrUsePriv->encColID();
                    log_request->enc_count = CurrUsePriv->updateEncCount();
                    log_request->enc_no_priv_flag =
                        CurrUsePriv->encLogPrivFlag();
                    log_request->sql_type = 2;
                    CurrUsePriv->setUpdateEncCount(0);
                    return 1;
                } else if (CurrUsePriv->deleteEncCount() &&
                           CurrUsePriv->isEncryptAudit(3)) {
                    log_request->enc_col_id = CurrUsePriv->encColID();
                    log_request->enc_count = CurrUsePriv->deleteEncCount();
                    log_request->enc_no_priv_flag =
                        CurrUsePriv->encLogPrivFlag();
                    log_request->sql_type = 3;
                    CurrUsePriv->setDeleteEncCount(0);
                    return 1;
                } else if (CurrUsePriv->selectEncCount() &&
                           CurrUsePriv->isEncryptAudit(4)) {
                    log_request->enc_col_id = CurrUsePriv->encColID();
                    log_request->enc_count = CurrUsePriv->selectEncCount();
                    log_request->enc_no_priv_flag =
                        CurrUsePriv->encLogPrivFlag();
                    log_request->sql_type = 4;
                    CurrUsePriv->setSelectEncCount(0);
                    return 1;
                } else if (CurrUsePriv->etcEncCount() &&
                           CurrUsePriv->isEncryptAudit(5)) {
                    log_request->enc_col_id = CurrUsePriv->encColID();
                    log_request->enc_count = CurrUsePriv->etcEncCount();
                    log_request->enc_no_priv_flag =
                        CurrUsePriv->encLogPrivFlag();
                    log_request->sql_type = 5;
                    CurrUsePriv->setEtcEncCount(0);
                    return 1;
                } else if (CurrUsePriv->insertDecCount() &&
                           CurrUsePriv->isDecryptAudit(1)) {
                    log_request->enc_col_id = CurrUsePriv->encColID();
                    log_request->dec_count = CurrUsePriv->insertDecCount();
                    log_request->dec_no_priv_flag =
                        CurrUsePriv->decLogPrivFlag();
                    log_request->sql_type = 1;
                    CurrUsePriv->setInsertDecCount(0);
                    return 1;
                } else if (CurrUsePriv->updateDecCount() &&
                           CurrUsePriv->isDecryptAudit(2)) {
                    log_request->enc_col_id = CurrUsePriv->encColID();
                    log_request->dec_count = CurrUsePriv->updateDecCount();
                    log_request->dec_no_priv_flag =
                        CurrUsePriv->decLogPrivFlag();
                    log_request->sql_type = 2;
                    CurrUsePriv->setUpdateDecCount(0);
                    return 1;
                } else if (CurrUsePriv->deleteDecCount() &&
                           CurrUsePriv->isDecryptAudit(3)) {
                    log_request->enc_col_id = CurrUsePriv->encColID();
                    log_request->dec_count = CurrUsePriv->deleteDecCount();
                    log_request->dec_no_priv_flag =
                        CurrUsePriv->decLogPrivFlag();
                    log_request->sql_type = 3;
                    CurrUsePriv->setDeleteDecCount(0);
                    return 1;
                } else if (CurrUsePriv->selectDecCount() &&
                           CurrUsePriv->isDecryptAudit(4)) {
                    log_request->enc_col_id = CurrUsePriv->encColID();
                    log_request->dec_count = CurrUsePriv->selectDecCount();
                    log_request->dec_no_priv_flag =
                        CurrUsePriv->decLogPrivFlag();
                    log_request->sql_type = 4;
                    CurrUsePriv->setSelectDecCount(0);
                    return 1;
                } else if (CurrUsePriv->etcDecCount() &&
                           CurrUsePriv->isDecryptAudit(5)) {
                    log_request->enc_col_id = CurrUsePriv->encColID();
                    log_request->dec_count = CurrUsePriv->etcDecCount();
                    log_request->dec_no_priv_flag =
                        CurrUsePriv->decLogPrivFlag();
                    log_request->sql_type = 5;
                    CurrUsePriv->setEtcDecCount(0);
                    return 1;
                }
                CurrUsePriv = CurrUsePriv->useList();
            }
        } else {
            while (CurrUsePriv) {
                dgt_sint32 set_flag = 0;
                if ((CurrUsePriv->encCount() &&
                     CurrUsePriv->isEncryptAudit(log_request->sql_type))) {
                    log_request->enc_col_id = CurrUsePriv->encColID();
                    log_request->enc_count = CurrUsePriv->encCount();
                    log_request->enc_no_priv_flag =
                        CurrUsePriv->encLogPrivFlag();
                    set_flag = 1;
                }
                if ((CurrUsePriv->decCount() &&
                     CurrUsePriv->isDecryptAudit(log_request->sql_type))) {
                    log_request->enc_col_id = CurrUsePriv->encColID();
                    log_request->dec_count = CurrUsePriv->decCount();
                    log_request->dec_no_priv_flag =
                        CurrUsePriv->decLogPrivFlag();
                    set_flag = 1;
                }
                if (set_flag) {
                    CurrUsePriv = CurrUsePriv->useList();
                    return 1;
                }
                CurrUsePriv = CurrUsePriv->useList();
            }
        }
        clearUseList();
        return 0;
    };
};

#endif
