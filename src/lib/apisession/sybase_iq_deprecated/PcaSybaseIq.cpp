
//
// c_dummy.cpp
//
// Copyright (c) 2009 Sybase, Inc.
// All rights reserved.
//

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "../../../../lib/cipher/sybase_iq_v4/extfnapiv4.h"
#include "PcAPI.h"

#if defined __cplusplus
extern "C" {
#endif

int extfn_use_new_api(void) { return EXTFN_V4_API; }

//  Corresponding SQL declaration:
//
//	CREATE FUNCTION PLS_ENCRYPT_B64_ID(IN src varchar(4000), IN enc_col_id int)
//			RETURNS varchar(4000)
//			DETERMINISTIC
//          		IGNORE NULL VALUES
//			EXTERNAL NAME 'pls_encrypt_b64_id@libPcaSybaseIq'
//

static void pls_encrypt_b64_id_evaluate(a_v3_extfn_scalar_context *cntxt,
                                        void *arg_handle) {
    an_extfn_value src_value;
    an_extfn_value enc_col_id_value;
    an_extfn_value outval;
    // get enc_col_id
    a_sql_int32 enc_col_id;
    (void)cntxt->get_value(arg_handle, 2, &enc_col_id_value);
    if (enc_col_id_value.data == NULL) {
        cntxt->set_error(cntxt, 20001, "enc_col_id is null");
        return;
    }
    enc_col_id = *((a_sql_int32 *)enc_col_id_value.data);

    // get src_data
    (void)cntxt->get_value(arg_handle, 1, &src_value);
    if (src_value.data == NULL) {
        return;
    }
    a_sql_int32 src_len;
    src_len = src_value.piece_len;
    if (src_len == 0) {
        outval.type = DT_VARCHAR;
        outval.piece_len = 0;
        outval.data = src_value.data;
        cntxt->set_value(arg_handle, &outval, 0);
        return;
    }

    int sid = 0;
    int rtn = 0;
    // Petra Get Session with Shared Session
    if ((sid = PcAPI_getSession("", "", "", "", "", "", 0)) < 0) {
        cntxt->set_error(cntxt, 20001, "Petra Get Session Failed");
        return;
    }
    // unsigned char* dst=0;
    unsigned char dst[4000];
    memset(dst, 0, 4000);

    unsigned int dst_len = 4000;
    // if ((rtn=PcAPI_encrypt_sess_buf(sid, enc_col_id, (unsigned
    // char*)src_value.data, src_len, &dst, &dst_len)) < 0) {
    if ((rtn = PcAPI_encrypt(sid, enc_col_id, (unsigned char *)src_value.data,
                             src_len, dst, &dst_len)) < 0) {
        cntxt->set_error(cntxt, 20001, "Petra Encrypt Failed");
        return;
    }
    // enc_data copy
    unsigned int idx = 0;
    for (idx = 0; idx < dst_len; idx++) {
        outval.type = DT_VARCHAR;
        outval.piece_len = 1;
        outval.data = &(dst[idx]);
        cntxt->set_value(arg_handle, &outval, idx);
    }
    if (dst_len == 0) {
        //
        // in case of char type
        // all padding space data
        //
        outval.type = DT_VARCHAR;
        outval.piece_len = 0;
        outval.data = src_value.data;
        cntxt->set_value(arg_handle, &outval, 0);
        return;
    }
}

static a_v3_extfn_scalar pls_encrypt_b64_id_descriptor = {
    0,   0, &pls_encrypt_b64_id_evaluate,
    0,    // Reserved - initialize to NULL
    0,    // Reserved - initialize to NULL
    0,    // Reserved - initialize to NULL
    0,    // Reserved - initialize to NULL
    0,    // Reserved - initialize to NULL
    NULL  // _for_server_internal_use
};

a_v3_extfn_scalar *pls_encrypt_b64_id() {
    return &pls_encrypt_b64_id_descriptor;
}

static void pls_decrypt_b64_id_evaluate(a_v3_extfn_scalar_context *cntxt,
                                        void *arg_handle) {
    an_extfn_value src_value;
    an_extfn_value enc_col_id_value;
    an_extfn_value outval;
    // get enc_col_id
    a_sql_int32 enc_col_id;
    (void)cntxt->get_value(arg_handle, 2, &enc_col_id_value);
    if (enc_col_id_value.data == NULL) {
        cntxt->set_error(cntxt, 20001, "enc_col_id is null");
        return;
    }
    enc_col_id = *((a_sql_int32 *)enc_col_id_value.data);

    // get src_data
    (void)cntxt->get_value(arg_handle, 1, &src_value);
    if (src_value.data == NULL) {
        return;
    }
    a_sql_int32 src_len;
    src_len = src_value.piece_len;

    if (src_len == 0) {
        outval.type = DT_VARCHAR;
        outval.piece_len = 0;
        outval.data = src_value.data;
        cntxt->set_value(arg_handle, &outval, 0);
        return;
    }

    int sid = 0;
    int rtn = 0;
    // Petra Get Session with Shared Session
    if ((sid = PcAPI_getSession("", "", "", "", "", "", 0)) < 0) {
        cntxt->set_error(cntxt, 20001, "Petra Get Session Failed");
        return;
    }
    unsigned char dst[4000];
    memset(dst, 0, 4000);
    unsigned int dst_len = 4000;
    if ((rtn = PcAPI_decrypt(sid, enc_col_id, (unsigned char *)src_value.data,
                             src_len, dst, &dst_len)) < 0) {
        cntxt->set_error(cntxt, 20001, "Petra Decrypt Failed");
        return;
    }
    // enc_data copy
    unsigned int idx = 0;
    for (idx = 0; idx < dst_len; idx++) {
        outval.type = DT_VARCHAR;
        outval.piece_len = 1;
        outval.data = &(dst[idx]);
        cntxt->set_value(arg_handle, &outval, idx);
    }
    if (dst_len == 0) {
        //
        // in case of char type
        // all padding space data
        //
        outval.type = DT_VARCHAR;
        outval.piece_len = 0;
        outval.data = src_value.data;
        cntxt->set_value(arg_handle, &outval, 0);
        return;
    }
}

static a_v3_extfn_scalar pls_decrypt_b64_id_descriptor = {
    0,   0, &pls_decrypt_b64_id_evaluate,
    0,    // Reserved - initialize to NULL
    0,    // Reserved - initialize to NULL
    0,    // Reserved - initialize to NULL
    0,    // Reserved - initialize to NULL
    0,    // Reserved - initialize to NULL
    NULL  // _for_server_internal_use
};

a_v3_extfn_scalar *pls_decrypt_b64_id() {
    return &pls_decrypt_b64_id_descriptor;
}

#if defined __cplusplus
}
#endif
