#include <ctype.h>
#include <string.h>

#include "PcaSessionPool.h"

#if defined __cplusplus
extern "C" {
#endif

char *ext_pls_encrypt_b64_id(char *src, int src_len, int enc_col_id,
                             int *err_code);
char *ext_pls_decrypt_b64_id(char *src, int src_len, int enc_col_id,
                             int *err_code);
int opn_session();
int db_sid = 0;

void entryfunction(char *func_name, int arg_count, void **args,
                   void **returnArg) {
    if (db_sid <= 0) {
        if ((db_sid = opn_session()) <= 0) {
            return;
        }
    }
    if (strcmp(func_name, "ext_pls_encrypt_b64_id") == 0) {
        if (returnArg != NULL) {
            *(char **)returnArg =
                ext_pls_encrypt_b64_id((char *)args[0], *((int *)args[1]),
                                       *((int *)args[2]), (int *)args[3]);
        }
    } else if (strcmp(func_name, "ext_pls_decrypt_b64_id") == 0) {
        if (returnArg != NULL) {
            *(char **)returnArg =
                ext_pls_decrypt_b64_id((char *)args[0], *((int *)args[1]),
                                       *((int *)args[2]), (int *)args[3]);
        }
    }
}

int opn_session() {
    pc_type_open_sess_in sess_in;
    memset(&sess_in, 0, sizeof(sess_in));
    sess_in.db_sid = 1;
    PcaSession *session = PcaSessionPool::openSession(sess_in.db_sid);
    if (!session) return -1;
    sprintf(sess_in.instance_name, "instance");
    sprintf(sess_in.db_name, "db_name");
    sprintf(sess_in.client_ip, "127.0.0.1");
    sprintf(sess_in.db_user, "db_user");
    sprintf(sess_in.os_user, "os_user");
    sprintf(sess_in.client_program, "program");
    sess_in.protocol = 3;
    sprintf(sess_in.user_id, "user_id");
    sprintf(sess_in.client_mac, "mac");
    return session->openSession(sess_in.db_sid, sess_in.instance_name,
                                sess_in.db_name, sess_in.client_ip,
                                sess_in.db_user, sess_in.os_user,
                                sess_in.client_program, sess_in.protocol,
                                sess_in.user_id, sess_in.client_mac);
}

dgt_schar enc_buf[4000];
char *ext_pls_encrypt_b64_id(char *src, int src_len, int enc_col_id,
                             int *err_code) {
    PcaSession *session = PcaSessionPool::getSession(db_sid);
    if (!session) {
        *err_code = -1;
        return 0;  // session not found error should be returned for ECODE
    }
    dgt_uint32 dst_len = 4000;
    memset(enc_buf, 0, 4000);
    if (session->encrypt(enc_col_id, (dgt_uint8 *)src, src_len,
                         (dgt_uint8 *)enc_buf, &dst_len) < 0) {
        //
        // encrypt failed, session has this last error code which can be gotten
        // by ECODE
        //
        *err_code = -2;
        return 0;
    } else if (dst_len == 0) {
        //
        // encrypted data is null
        //
        return 0;
    }
    return enc_buf;
}

dgt_schar dec_buf[4000];
char *ext_pls_decrypt_b64_id(char *src, int src_len, int enc_col_id,
                             int *err_code) {
    PcaSession *session = PcaSessionPool::getSession(db_sid);
    if (!session) {
        *err_code = -1;
        return 0;  // session not found error should be returned for ECODE
    }
    dgt_uint32 dst_len = 4000;
    memset(dec_buf, 0, 4000);
    if (session->decrypt(enc_col_id, (dgt_uint8 *)src, src_len,
                         (dgt_uint8 *)dec_buf, &dst_len) < 0) {
        //
        // encrypt failed, session has this last error code which can be gotten
        // by ECODE
        //
        *err_code = -2;
        return 0;
    } else if (dst_len == 0) {
        //
        // encrypted data is null
        //
        return 0;
    }
    return dec_buf;
}

#if defined __cplusplus
}
#endif
