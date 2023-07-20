#include "sinsiway_PcaSession.h"

#include "PcaSessionPool.h"
#include "PccFileCryptor.h"

static const int PcAPI_ERR_INVALID_SID = -30302;

/*
 * Class:     sinsiway_PcaSession
 * Method:    INIT
 * Signature: ([B[B)I
 */
JNIEXPORT jint JNICALL
Java_sinsiway_PcaSession_INIT(JNIEnv *env, jclass jc, jbyteArray conf_file_path,
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
 * Class:     sinsiway_PcaSession
 * Method:    OPN
 * Signature: (I[B[B[B[B[BI[B[B)I
 */
JNIEXPORT jint JNICALL Java_sinsiway_PcaSession_OPN(
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
    //	return session->openSession(sess_in.db_sid, sess_in.instance_name,
    //sess_in.db_name, sess_in.client_ip, sess_in.db_user, 			sess_in.os_user,
    //sess_in.client_program, sess_in.protocol, sess_in.user_id,
    //sess_in.client_mac);
    dgt_sint32 rtn = session->openSession(
        sess_in.db_sid, sess_in.instance_name, sess_in.db_name,
        sess_in.client_ip, sess_in.db_user, sess_in.os_user,
        sess_in.client_program, sess_in.protocol, sess_in.user_id,
        sess_in.client_mac);
    // added by shson 2018.10.01 for use api session for cryptFile
    dgt_sint32 api_sid = PcaApiSessionPool::getApiSession(
        sess_in.client_ip, "", sess_in.client_program, "", "", sess_in.os_user,
        0);
    session->setApiSid(api_sid);

    return rtn;
}

/*
 * Class:     sinsiway_PcaSession
 * Method:    CLS
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_sinsiway_PcaSession_CLS(JNIEnv *env, jclass jc,
                                                    jint db_sid) {
    PcaSessionPool::closeSession(db_sid);
}

/*
 * Class:     sinsiway_PcaSession
 * Method:    ENC
 * Signature: (II[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_sinsiway_PcaSession_ENC__II_3B(
    JNIEnv *env, jclass jc, jint db_sid, jint enc_col_id, jbyteArray src) {
    PcaSession *session = PcaSessionPool::getSession(db_sid, 1);
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
 * Class:     sinsiway_PcaSession
 * Method:    ENC_NM
 * Signature: (I[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_sinsiway_PcaSession_ENC_1NM(JNIEnv *env, jclass jc, jint db_sid,
                                 jbyteArray enc_col_name, jbyteArray src) {
    PcaSession *session = PcaSessionPool::getSession(db_sid, 1);
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
 * Class:     sinsiway_PcaSession
 * Method:    DEC
 * Signature: (II[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_sinsiway_PcaSession_DEC__II_3B(
    JNIEnv *env, jclass jc, jint db_sid, jint enc_col_id, jbyteArray src) {
    PcaSession *session = PcaSessionPool::getSession(db_sid, 1);
    if (!session) return 0;
    dgt_uint32 dst_len = 0;
    dgt_uint8 *dst = 0;
    dgt_sint32 in_len = env->GetArrayLength(src);
    dgt_uint8 *in_buffer = session->inBuffer(in_len);
    env->GetByteArrayRegion(src, 0, in_len, (jbyte *)in_buffer);
    if (session->decrypt(enc_col_id, in_buffer, in_len, &dst, &dst_len) < 0)
        return 0;
    else if (dst_len == 0)
        return 0;
    jbyteArray decrypted_data = env->NewByteArray(dst_len);
    env->SetByteArrayRegion(decrypted_data, 0, dst_len, (jbyte *)dst);
    return decrypted_data;
}

/*
 * Class:     sinsiway_PcaSession
 * Method:    DEC_NM
 * Signature: (I[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_sinsiway_PcaSession_DEC_1NM(JNIEnv *env, jclass jc, jint db_sid,
                                 jbyteArray enc_col_name, jbyteArray src) {
    PcaSession *session = PcaSessionPool::getSession(db_sid, 1);
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
    if (session->decrypt(ecn, in_buffer, in_len, &dst, &dst_len) < 0)
        return 0;
    else if (dst_len == 0)
        return 0;
    jbyteArray decrypted_data = env->NewByteArray(dst_len);
    env->SetByteArrayRegion(decrypted_data, 0, dst_len, (jbyte *)dst);
    return decrypted_data;
}

/*
 * Class:     sinsiway_PcaSession
 * Method:    ECODE
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_sinsiway_PcaSession_ECODE(JNIEnv *env, jclass jc,
                                                      jint db_sid) {
    PcaSession *session = PcaSessionPool::getSession(db_sid, 1);
    if (!session) return PcAPI_ERR_INVALID_SID;
    return session->getErrCode();
}

/*
 * Class:     sinsiway_PcaSession
 * Method:    CRYPTFILE
 * Signature: (I[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_sinsiway_PcaSession_CRYPTFILE(
    JNIEnv *env, jclass jc, jint db_sid, jbyteArray param_string,
    jbyteArray input_file_path, jbyteArray output_file_path) {
    PcaSession *pca_session = PcaSessionPool::getSession(db_sid, 1);
    if (!pca_session)
        return 0;  // session not found error should be returned for ECODE
    dgt_sint32 api_sid = pca_session->getApiSid();
    PcaApiSession *session = PcaApiSessionPool::getApiSession(api_sid);
    if (!session) return 0;

    PccFileCryptor cryptor;
    dgt_sint32 in_len = env->GetArrayLength(param_string);
    dgt_uint8 parameters[1024];
    memset(parameters, 0, 1024);
    env->GetByteArrayRegion(param_string, 0, in_len, (jbyte *)parameters);
    in_len = env->GetArrayLength(input_file_path);
    if (in_len > 1024) return -66707;
    dgt_uint8 *in_file = 0;
    if (in_len > 0) {
        in_file = new dgt_uint8[in_len + 1];
        memset(in_file, 0, in_len + 1);
        env->GetByteArrayRegion(input_file_path, 0, in_len, (jbyte *)in_file);
    }
    in_len = env->GetArrayLength(output_file_path);
    if (in_len > 1024) {
        if (in_file) delete in_file;
        return -66707;
    }
    dgt_uint8 *out_file = 0;
    if (in_len > 0) {
        out_file = new dgt_uint8[in_len + 1];
        memset(out_file, 0, in_len + 1);
        env->GetByteArrayRegion(output_file_path, 0, in_len, (jbyte *)out_file);
    }
    if (cryptor.crypt(api_sid, (const dgt_schar *)parameters,
                      (const dgt_schar *)in_file,
                      (const dgt_schar *)out_file) < 0) {
        int rtn = cryptor.errCode();
        if (rtn != PFC_DVS_ERR_CODE_ZERO_FILE_SIZE) {
            if (in_file) delete in_file;
            if (out_file) delete out_file;
            return rtn;
        }
    }
    if (in_file) delete in_file;
    if (out_file) delete out_file;
    return 0;
}

/*
 * Class:     sinsiway_PcaSession
 * Method:    ISENCRYPTED
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_sinsiway_PcaSession_ISENCRYPTED(
    JNIEnv *env, jclass jc, jbyteArray file_name) {
    dgt_sint32 file_name_len = env->GetArrayLength(file_name);
    if (file_name_len > 1024) return -66707;
    dgt_schar infile_name[1025];
    memset(infile_name, 0, 1025);

    env->GetByteArrayRegion(file_name, 0, file_name_len, (jbyte *)infile_name);
    return PccHeaderManager::isEncrypted(infile_name);
}

/*
 * Class:     sinsiway_PcaSession
 * Method:    NSS
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_sinsiway_PcaSession_NSS(JNIEnv *env, jclass jc) {
    return PcaSessionPool::numSharedSession();
}

/*
 * Class:     sinsiway_PcaSession
 * Method:    MAXPS
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_sinsiway_PcaSession_MAXPS(JNIEnv *env, jclass jc) {
    return PcaSessionPool::maxPrivateSession();
}