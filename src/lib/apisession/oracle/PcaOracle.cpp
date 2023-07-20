#include "PcaOracle.h"

#include "PcaSessionPool.h"

static const int PcAPI_ERR_INVALID_SID = -30302;

/*
 * Class:     PcaOracle
 * Method:    INIT
 * Signature: ([B[B)I
 */
JNIEXPORT jint JNICALL Java_PcaOracle_INIT(JNIEnv *env, jclass jc,
                                           jbyteArray conf_file_path,
                                           jbyteArray credentials_password) {
    dgt_schar cfp[257];
    dgt_schar cpw[33];
    dgt_sint32 blen;
    if ((blen = env->GetArrayLength(conf_file_path)) > 256) blen = 256;
    memset(cfp, 0, 257);
    env->GetByteArrayRegion(conf_file_path, 0, blen, (jbyte *)cfp);
    if ((blen = env->GetArrayLength(credentials_password)) > 32) blen = 32;
    memset(cpw, 0, 33);
    env->GetByteArrayRegion(credentials_password, 0, blen, (jbyte *)cpw);
    return PcaSessionPool::initialize(cfp, cpw);
}

/*
 * Class:     PcaOracle
 * Method:    OPN
 * Signature: (I[B[B[B[B[BI[B[B)I
 */
JNIEXPORT jint JNICALL Java_PcaOracle_OPN(
    JNIEnv *env, jclass jc, jint db_sid, jbyteArray instance_name,
    jbyteArray db_name, jbyteArray client_ip, jbyteArray db_user,
    jbyteArray os_user, jbyteArray client_program, jint protocol,
    jbyteArray user_id, jbyteArray client_mac) {
    pc_type_open_sess_in sess_in;
    dgt_sint32 blen;
    memset(&sess_in, 0, sizeof(sess_in));
    sess_in.db_sid = db_sid;
    if ((blen = env->GetArrayLength(instance_name)) > 32) blen = 32;
    env->GetByteArrayRegion(instance_name, 0, blen,
                            (jbyte *)sess_in.instance_name);
    if ((blen = env->GetArrayLength(db_name)) > 32) blen = 32;
    env->GetByteArrayRegion(db_name, 0, blen, (jbyte *)sess_in.db_name);
    if ((blen = env->GetArrayLength(client_ip)) > 64) blen = 64;
    env->GetByteArrayRegion(client_ip, 0, blen, (jbyte *)sess_in.client_ip);
    if ((blen = env->GetArrayLength(db_user)) > 32) blen = 32;
    env->GetByteArrayRegion(db_user, 0, blen, (jbyte *)sess_in.db_user);
    if ((blen = env->GetArrayLength(os_user)) > 32) blen = 32;
    env->GetByteArrayRegion(os_user, 0, blen, (jbyte *)sess_in.os_user);
    if ((blen = env->GetArrayLength(client_program)) > 128) blen = 128;
    env->GetByteArrayRegion(client_program, 0, blen,
                            (jbyte *)sess_in.client_program);
    sess_in.protocol = (dgt_uint8)protocol;
    if ((blen = env->GetArrayLength(user_id)) > 32) blen = 32;
    env->GetByteArrayRegion(user_id, 0, blen, (jbyte *)sess_in.user_id);
    if ((blen = env->GetArrayLength(client_mac)) > 64) blen = 64;
    env->GetByteArrayRegion(client_mac, 0, blen, (jbyte *)sess_in.client_mac);

    PcaSession *session = PcaSessionPool::openSession(sess_in.db_sid);
    if (!session) return PcAPI_ERR_INVALID_SID;
    return session->openSession(sess_in.db_sid, sess_in.instance_name,
                                sess_in.db_name, sess_in.client_ip,
                                sess_in.db_user, sess_in.os_user,
                                sess_in.client_program, sess_in.protocol,
                                sess_in.user_id, sess_in.client_mac);
}

/*
 * Class:     PcaOracle
 * Method:    CLS
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_PcaOracle_CLS(JNIEnv *env, jclass jc, jint db_sid) {
    PcaSessionPool::closeSession(db_sid);
}

/*
 * Class:     PcaOracle
 * Method:    CCS
 * Signature: (I[B)V
 */
JNIEXPORT void JNICALL Java_PcaOracle_CCS(JNIEnv *env, jclass jc, jint db_sid,
                                          jbyteArray char_set_bytes) {
    PcaSession *session = PcaSessionPool::getSession(db_sid);
    if (session) {
        dgt_schar char_set[33];
        memset(char_set, 0, 33);
        env->GetByteArrayRegion(char_set_bytes, 0,
                                env->GetArrayLength(char_set_bytes),
                                (jbyte *)char_set);
        session->setCharSet(char_set);
    }
}

/*
 * Class:     PcaOracle
 * Method:    ENC
 * Signature: (II[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_PcaOracle_ENC(JNIEnv *env, jclass jc,
                                                jint db_sid, jint enc_col_id,
                                                jbyteArray src) {
    PcaSession *session = PcaSessionPool::getSession(db_sid);
    if (!session)
        return 0;  // session not found error should be returned for ECODE
    dgt_uint32 dst_len = 0;
    dgt_uint8 *dst = 0;
    dgt_sint32 in_len = env->GetArrayLength(src);
    dgt_uint8 *in_buffer = session->inBuffer(in_len);
    env->GetByteArrayRegion(src, 0, in_len, (jbyte *)in_buffer);
    if (session->encrypt(enc_col_id, in_buffer, in_len, &dst, &dst_len) < 0) {
        //
        // encrypt failed, session has this last error code which can be gotten
        // by ECODE
        //
        return 0;
    } else if (dst_len == 0) {
        //
        // encrypted data is null
        //
        return 0;
    }
    jbyteArray encrypted_data = env->NewByteArray(dst_len);
    env->SetByteArrayRegion(encrypted_data, 0, dst_len, (jbyte *)dst);
    return encrypted_data;
}

/*
 * Class:     PcaOracle
 * Method:    ENC_C
 * Signature: (II[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_PcaOracle_ENC_1C(JNIEnv *env, jclass jc,
                                                   jint db_sid, jint enc_col_id,
                                                   jbyteArray src) {
    PcaSession *session = PcaSessionPool::getSession(db_sid);
    if (!session)
        return 0;  // session not found error should be returned for ECODE
    dgt_uint32 dst_len = 0;
    dgt_uint8 *dst = 0;
    dgt_sint32 in_len = env->GetArrayLength(src);
    dgt_uint8 *in_buffer = session->inBuffer(in_len);
    env->GetByteArrayRegion(src, 0, in_len, (jbyte *)in_buffer);
    if (session->encrypt_c(enc_col_id, in_buffer, in_len, &dst, &dst_len) < 0) {
        //
        // encrypt failed, session has this last error code which can be gotten
        // by ECODE
        //
        return 0;
    } else if (dst_len == 0) {
        //
        // encrypted data is null
        //
        return 0;
    }
    jbyteArray encrypted_data = env->NewByteArray(dst_len);
    env->SetByteArrayRegion(encrypted_data, 0, dst_len, (jbyte *)dst);
    return encrypted_data;
}

JNIEXPORT jbyteArray JNICALL Java_PcaOracle_ENC_1NM(JNIEnv *env, jclass jc,
                                                    jint db_sid,
                                                    jbyteArray enc_col_name,
                                                    jbyteArray src) {
    PcaSession *session = PcaSessionPool::getSession(db_sid);
    if (!session)
        return 0;  // session not found error should be returned for ECODE
    dgt_uint32 dst_len = 0;
    dgt_uint8 *dst = 0;
    dgt_sint32 in_len = env->GetArrayLength(src);
    dgt_uint8 *in_buffer = session->inBuffer(in_len);
    dgt_schar ecn[132];
    memset(ecn, 0, 132);
    env->GetByteArrayRegion(enc_col_name, 0, env->GetArrayLength(enc_col_name),
                            (jbyte *)ecn);
    env->GetByteArrayRegion(src, 0, in_len, (jbyte *)in_buffer);
    if (session->encrypt(ecn, in_buffer, in_len, &dst, &dst_len) < 0) {
        //
        // encrypt failed, session has this last error code which can be gotten
        // by ECODE
        //
        return 0;
    } else if (dst_len == 0) {
        //
        // encrypted data is null
        //
        return 0;
    }
    jbyteArray encrypted_data = env->NewByteArray(dst_len);
    env->SetByteArrayRegion(encrypted_data, 0, dst_len, (jbyte *)dst);
    return encrypted_data;
}

/*
 * Class:     PcaOracle
 * Method:    DEC
 * Signature: (II[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_PcaOracle_DEC(JNIEnv *env, jclass jc,
                                                jint db_sid, jint enc_col_id,
                                                jbyteArray src) {
    PcaSession *session = PcaSessionPool::getSession(db_sid);
    if (!session) return 0;
    dgt_uint32 dst_len = 0;
    dgt_uint8 *dst = 0;
    dgt_sint32 in_len = env->GetArrayLength(src);
    dgt_uint8 *in_buffer = session->inBuffer(in_len);
    env->GetByteArrayRegion(src, 0, in_len, (jbyte *)in_buffer);
    if (session->decrypt(enc_col_id, in_buffer, in_len, &dst, &dst_len) < 0) {
        return 0;
    } else if (dst_len == 0) {
        return 0;
    }
    jbyteArray decrypted_data = env->NewByteArray(dst_len);
    env->SetByteArrayRegion(decrypted_data, 0, dst_len, (jbyte *)dst);
    return decrypted_data;
}

JNIEXPORT jbyteArray JNICALL Java_PcaOracle_DEC_1NM(JNIEnv *env, jclass jc,
                                                    jint db_sid,
                                                    jbyteArray enc_col_name,
                                                    jbyteArray src) {
    PcaSession *session = PcaSessionPool::getSession(db_sid);
    if (!session) return 0;
    dgt_uint32 dst_len = 0;
    dgt_uint8 *dst = 0;
    dgt_sint32 in_len = env->GetArrayLength(src);
    dgt_uint8 *in_buffer = session->inBuffer(in_len);
    dgt_schar ecn[132];
    memset(ecn, 0, 132);
    env->GetByteArrayRegion(enc_col_name, 0, env->GetArrayLength(enc_col_name),
                            (jbyte *)ecn);
    env->GetByteArrayRegion(src, 0, in_len, (jbyte *)in_buffer);
    if (session->decrypt(ecn, in_buffer, in_len, &dst, &dst_len) < 0) {
        return 0;
    } else if (dst_len == 0) {
        return 0;
    }
    jbyteArray decrypted_data = env->NewByteArray(dst_len);
    env->SetByteArrayRegion(decrypted_data, 0, dst_len, (jbyte *)dst);
    return decrypted_data;
}

/*
 * Class:     PcaOracle
 * Method:    OPHUEK
 * Signature: (II[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_PcaOracle_OPHUEK(JNIEnv *env, jclass jc,
                                                   jint db_sid, jint enc_col_id,
                                                   jbyteArray src,
                                                   jint src_enc_flag) {
    PcaSession *session = PcaSessionPool::getSession(db_sid);
    if (!session) return 0;
    dgt_uint32 dst_len = 0;
    dgt_uint8 *dst = 0;
    dgt_sint32 in_len = env->GetArrayLength(src);
    dgt_uint8 *in_buffer = session->inBuffer(in_len);
    env->GetByteArrayRegion(src, 0, in_len, (jbyte *)in_buffer);
    if (session->OPHUEK(enc_col_id, in_buffer, in_len, &dst, &dst_len,
                        src_enc_flag) < 0) {
        return 0;
    } else if (dst_len == 0) {
        return 0;
    }
    jbyteArray hash_data = env->NewByteArray(dst_len);
    env->SetByteArrayRegion(hash_data, 0, dst_len, (jbyte *)dst);
    return hash_data;
}

JNIEXPORT jbyteArray JNICALL Java_PcaOracle_OPHUEK_1NM(JNIEnv *env, jclass jc,
                                                       jint db_sid,
                                                       jbyteArray enc_col_name,
                                                       jbyteArray src,
                                                       jint src_enc_flag) {
    PcaSession *session = PcaSessionPool::getSession(db_sid);
    if (!session) return 0;
    dgt_uint32 dst_len = 0;
    dgt_uint8 *dst = 0;
    dgt_sint32 in_len = env->GetArrayLength(src);
    dgt_uint8 *in_buffer = session->inBuffer(in_len);
    dgt_schar ecn[132];
    memset(ecn, 0, 132);
    env->GetByteArrayRegion(enc_col_name, 0, env->GetArrayLength(enc_col_name),
                            (jbyte *)ecn);
    env->GetByteArrayRegion(src, 0, in_len, (jbyte *)in_buffer);
    if (session->OPHUEK(ecn, in_buffer, in_len, &dst, &dst_len, src_enc_flag) <
        0) {
        return 0;
    } else if (dst_len == 0) {
        return 0;
    }
    jbyteArray hash_data = env->NewByteArray(dst_len);
    env->SetByteArrayRegion(hash_data, 0, dst_len, (jbyte *)dst);
    return hash_data;
}

/*
 * Class:     PcaOracle
 * Method:    ENC_CPN
 * Signature: (II[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_PcaOracle_ENC_1CPN(JNIEnv *env, jclass jc,
                                                     jint db_sid,
                                                     jint enc_col_id,
                                                     jbyteArray src) {
    PcaSession *session = PcaSessionPool::getSession(db_sid);
    if (!session) return 0;
    dgt_uint32 dst_len = 0;
    dgt_uint8 *dst = 0;
    dgt_sint32 in_len = env->GetArrayLength(src);
    dgt_uint8 *in_buffer = session->inBuffer(in_len);
    env->GetByteArrayRegion(src, 0, in_len, (jbyte *)in_buffer);
    if (session->encryptCpn(enc_col_id, in_buffer, in_len, &dst, &dst_len) <
        0) {
        return 0;
    } else if (dst_len == 0) {
        return 0;
    }
    jbyteArray coupon_data = env->NewByteArray(dst_len);
    env->SetByteArrayRegion(coupon_data, 0, dst_len, (jbyte *)dst);
    return coupon_data;
}

JNIEXPORT jbyteArray JNICALL
Java_PcaOracle_ENC_1CPN_1NM(JNIEnv *env, jclass jc, jint db_sid,
                            jbyteArray enc_col_name, jbyteArray src) {
    PcaSession *session = PcaSessionPool::getSession(db_sid);
    if (!session) return 0;
    dgt_uint32 dst_len = 0;
    dgt_uint8 *dst = 0;
    dgt_sint32 in_len = env->GetArrayLength(src);
    dgt_uint8 *in_buffer = session->inBuffer(in_len);
    dgt_schar ecn[132];
    memset(ecn, 0, 132);
    env->GetByteArrayRegion(enc_col_name, 0, env->GetArrayLength(enc_col_name),
                            (jbyte *)ecn);
    env->GetByteArrayRegion(src, 0, in_len, (jbyte *)in_buffer);
    if (session->encryptCpn(ecn, in_buffer, in_len, &dst, &dst_len) < 0) {
        return 0;
    } else if (dst_len == 0) {
        return 0;
    }
    jbyteArray coupon_data = env->NewByteArray(dst_len);
    env->SetByteArrayRegion(coupon_data, 0, dst_len, (jbyte *)dst);
    return coupon_data;
}

/*
 * Class:     PcaOracle
 * Method:    DEC_CPN
 * Signature: (II[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_PcaOracle_DEC_1CPN(JNIEnv *env, jclass jc,
                                                     jint db_sid,
                                                     jint enc_col_id,
                                                     jbyteArray src) {
    PcaSession *session = PcaSessionPool::getSession(db_sid);
    if (!session) return 0;
    dgt_uint32 dst_len = 0;
    dgt_uint8 *dst = 0;
    dgt_sint32 in_len = env->GetArrayLength(src);
    dgt_uint8 *in_buffer = session->inBuffer(in_len);
    env->GetByteArrayRegion(src, 0, in_len, (jbyte *)in_buffer);
    if (session->decryptCpn(enc_col_id, in_buffer, in_len, &dst, &dst_len) <
        0) {
        return 0;
    } else if (dst_len == 0) {
        return 0;
    }
    jbyteArray decrypted_data = env->NewByteArray(dst_len);
    env->SetByteArrayRegion(decrypted_data, 0, dst_len, (jbyte *)dst);
    return decrypted_data;
}

JNIEXPORT jbyteArray JNICALL
Java_PcaOracle_DEC_1CPN_1NM(JNIEnv *env, jclass jc, jint db_sid,
                            jbyteArray enc_col_name, jbyteArray src) {
    PcaSession *session = PcaSessionPool::getSession(db_sid);
    if (!session) return 0;
    dgt_uint32 dst_len = 0;
    dgt_uint8 *dst = 0;
    dgt_sint32 in_len = env->GetArrayLength(src);
    dgt_uint8 *in_buffer = session->inBuffer(in_len);
    dgt_schar ecn[132];
    memset(ecn, 0, 132);
    env->GetByteArrayRegion(enc_col_name, 0, env->GetArrayLength(enc_col_name),
                            (jbyte *)ecn);
    env->GetByteArrayRegion(src, 0, in_len, (jbyte *)in_buffer);
    if (session->decryptCpn(ecn, in_buffer, in_len, &dst, &dst_len) < 0) {
        return 0;
    } else if (dst_len == 0) {
        return 0;
    }
    jbyteArray decrypted_data = env->NewByteArray(dst_len);
    env->SetByteArrayRegion(decrypted_data, 0, dst_len, (jbyte *)dst);
    return decrypted_data;
}

/*
 * Class:     PcaOracle
 * Method:    SSHT64
 * Signature: (I[BI)I
 */
JNIEXPORT jint JNICALL Java_PcaOracle_SSHT64(JNIEnv *env, jclass jc,
                                             jint db_sid, jbyteArray sql_hash,
                                             jint sql_type) {
    PcaSession *session = PcaSessionPool::getSession(db_sid);
    if (!session) return PcAPI_ERR_INVALID_SID;
    dgt_schar sh[65];
    dgt_sint32 blen;
    if ((blen = env->GetArrayLength(sql_hash)) > 64) blen = 64;
    memset(sh, 0, 65);
    env->GetByteArrayRegion(sql_hash, 0, blen, (jbyte *)sh);
    session->setSqlHash(sh, sql_type);
    return 0;
}

/*
 * Class:     PcaOracle
 * Method:    LCR
 * Signature: (I[BI)V
 */
JNIEXPORT jint JNICALL Java_PcaOracle_LCR64(JNIEnv *env, jclass jc, jint db_sid,
                                            jbyteArray sql_hash,
                                            jint sql_type) {
    PcaSession *session = PcaSessionPool::getSession(db_sid);
    if (!session) return PcAPI_ERR_INVALID_SID;
    dgt_schar sh[65];
    dgt_sint32 blen;
    if ((blen = env->GetArrayLength(sql_hash)) > 64) blen = 64;
    memset(sh, 0, 65);
    env->GetByteArrayRegion(sql_hash, 0, blen, (jbyte *)sh);
    session->logCurrRequest(sh, sql_type);
    return 0;
}

/*
 * Class:     PcaOracle
 * Method:    ECODE
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_PcaOracle_ECODE(JNIEnv *env, jclass jc,
                                            jint db_sid) {
    PcaSession *session = PcaSessionPool::getSession(db_sid);
    if (!session) return PcAPI_ERR_INVALID_SID;
    return session->getErrCode();
}

/*
 * Class:     PcaOracle
 * Method:    GNSF
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_PcaOracle_GNSF(JNIEnv *env, jclass jc,
                                           jint db_sid) {
    PcaSession *session = PcaSessionPool::getSession(db_sid);
    if (session) return session->getNewSqlFlag();
    return 0;
}

/*
 * Class:     PcaOracle
 * Method:    LOGGING
 * Signature: (I[B)V
 */
JNIEXPORT void JNICALL Java_PcaOracle_LOGGING(JNIEnv *env, jclass jc,
                                              jint ecode, jbyteArray msg) {
    dgt_schar m[257];
    dgt_sint32 blen;
    if ((blen = env->GetArrayLength(msg)) > 256) blen = 256;
    memset(m, 0, 257);
    env->GetByteArrayRegion(msg, 0, blen, (jbyte *)m);
    PcaKeySvrSessionPool::logging(ecode, m);
}
