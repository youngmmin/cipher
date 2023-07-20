/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PcaSession
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 4. 5
 *   Description        :       petra cipher API session
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcaSession.h"

PcaPrivilege* PcaSession::getPrivilege(dgt_sint64 enc_col_id,
                                       dgt_sint32 sql_type) {
    PcaPrivilege* priv = 0;
    if ((ErrCode = PrivilegePool.getPriv(enc_col_id, &priv))) {
        PcaKeySvrSessionPool::logging(
            ErrCode, "getPriv failed: failed to lock the privilege pool");
        return 0;
    }
    if (!priv || !priv->isPrivEffective()) {
        //
        // priv that's no more effective is a target to get its privilege
        //
        PcaKeySvrSession* svr_session = 0;
        if (!(ErrCode = KeySvrSessionPool->getSession(&svr_session))) {
            pc_type_get_priv_out priv_out;
            dgt_sint32 retry_cnt = 0;
            memset(&priv_out, 0, sizeof(priv_out));
            while ((ErrCode =
                        svr_session->getPriv(UserSID, enc_col_id, &priv_out))) {
                PcaKeySvrSessionPool::logging(ErrCode, svr_session->errMsg());
                if (ErrCode == PcaKeySvrSession::PKSS_SESSION_NOT_FOUND &&
                    retry_cnt++ == 0) {
                    //
                    // added by chchung 2012.10.11
                    //
                    // session user or encrypt column not found
                    // the current key server is not the owner of UserSID
                    // so retry after opening a new session
                    //
                    pc_type_open_sess_out sess_out;
                    memset(&sess_out, 0, sizeof(pc_type_open_sess_out));
                    if ((ErrCode = svr_session->openSession(
                             SessInfo.db_sid, SessInfo.instance_name,
                             SessInfo.db_name, SessInfo.client_ip,
                             SessInfo.db_user, SessInfo.os_user,
                             SessInfo.client_program, SessInfo.protocol,
                             SessInfo.user_id, SessInfo.client_mac,
                             &sess_out)) == 0) {
                        //
                        // open a new session
                        //
                        UserSID = sess_out.user_sid;
                        AuthFailCode = sess_out.auth_fail_code;
                        continue;
                    } else {
                        PcaKeySvrSessionPool::logging(ErrCode,
                                                      svr_session->errMsg());
                    }
                }
                break;
            }
            KeySvrSessionPool->returnSession(svr_session);
            if (PcaKeySvrSessionPool::traceLevel() > 1) {
                PcaKeySvrSessionPool::logging(
                    "SID[%d]:: getPriv => UserSID[%lld] EncColID[%lld] "
                    "ErrCode[%d]",
                    SID, UserSID, enc_col_id, ErrCode);
                if (ErrCode == 0) {
                    PcaKeySvrSessionPool::logging(
                        "\nSID[%d]:: priv => kid[%lld] MaxColLen[%u] "
                        "AltThreshold[%u] maskingThreshold[%u] \n"
                        "ColType[%d] Multibyte[%d] EncPriv[%d] DecPriv[%d] "
                        "AuthFailEncPriv[%d] AuthFailDecPriv[%d] "
                        "EncNoPrivAlert[%d] DecNoPrivAlert[%d]\n"
                        "enc_audit_flag[%d],dec_audit_flag[%d],OphuekFlag[%d]\n"
                        "enc_day[%d] enc_start_time[%d] enc_start_min[%d] "
                        "enc_end_hour[%d] enc_end_min[%d] "
                        "enc_contrary_flag[%d]\n"
                        "dec_dey[%d] dec_start_time[%d] dec_start_min[%d] "
                        "dec_end_hour[%d] dec_end_min[%d] "
                        "dec_contrary_flag[%d]\n",
                        SID, priv_out.key_id, priv_out.max_col_len,
                        priv_out.dec_alt_threshold,
                        priv_out.dec_masking_threshold, priv_out.col_type,
                        priv_out.multibyte_flag, priv_out.enc_priv,
                        priv_out.dec_priv, priv_out.auth_fail_enc_priv,
                        priv_out.auth_fail_dec_priv, priv_out.enc_no_priv_alert,
                        priv_out.dec_no_priv_alert, priv_out.enc_audit_flag,
                        priv_out.dec_audit_flag, priv_out.ophuek_flag,
                        priv_out.week_map[0], priv_out.week_map[1],
                        priv_out.week_map[2], priv_out.week_map[3],
                        priv_out.week_map[4], priv_out.week_map[5],
                        priv_out.week_map[6], priv_out.week_map[7],
                        priv_out.week_map[8], priv_out.week_map[9],
                        priv_out.week_map[10], priv_out.week_map[11]);
                }
            }
            if (ErrCode) {
                //
                // in case of failure while fetching privilege,
                // in which "priv" could have an pointer to the old priv.
                // so clear it;
                //
                // priv = 0;
                if (priv) ErrCode = 0;  // it's better to reuse old privilege
            } else {
                //
                // just in case of no error in getPriv
                //
                if (priv) {
                    priv->setPrivilege(&priv_out);
                } else {
                    //
                    // get an enyption column key from the key manager newly.
                    // register it with the key hash table.
                    //
                    dgt_uint8 multi_byte_size = 0;
                    if (!strcasecmp(SessCharSet, "UTF-8"))
                        multi_byte_size = 3;
                    else
                        multi_byte_size = 2;
                    if ((ErrCode = PrivilegePool.putPriv(
                             new PcaPrivilege(enc_col_id, &priv_out, KeyPool,
                                              IVPool, multi_byte_size),
                             &priv))) {
                        PcaKeySvrSessionPool::logging(
                            ErrCode,
                            "putPriv failed: failed to lock the privilege "
                            "pool");
                    }
                }
            }

        } else {
            //
            // in case of no available key server session, in which "priv" has
            // an pointer to the old priv
            //
            // priv = 0;
            if (priv) ErrCode = 0;  // it's better to reuse old privilege
        }
    }
    return priv;
}

PcaPrivilege* PcaSession::getVKeyPrivilege(
    dgt_sint64 virtual_key_id, dgt_uint8 crypt_type, dgt_uint8 target_type,
    dgt_schar* name1, dgt_schar* name2, dgt_schar* name3, dgt_schar* name4,
    dgt_schar* name5, dgt_schar* name6, dgt_schar* name7, dgt_schar* name8,
    dgt_schar* name9, dgt_schar* name10) {
    PcaPrivilege* priv = 0;
    if ((ErrCode = PrivilegePool.getVKeyPriv(virtual_key_id, &priv))) {
        PcaKeySvrSessionPool::logging(
            ErrCode, "getPriv failed: failed to lock the privilege pool");
        return 0;
    }
    if (!priv || !priv->isPrivEffective()) {
        //
        // priv that's no more effective is a target to get its privilege
        //
        PcaKeySvrSession* svr_session = 0;
        if (!(ErrCode = KeySvrSessionPool->getSession(&svr_session))) {
            pc_type_get_vkey_priv_out vkey_priv_out;
            dgt_sint32 retry_cnt = 0;
            memset(&vkey_priv_out, 0, sizeof(vkey_priv_out));
            while ((ErrCode = svr_session->getVKeyPriv(
                        UserSID, virtual_key_id, crypt_type, &vkey_priv_out,
                        target_type, name1, name2, name3, name4, name5, name6,
                        name7, name8, name9, name10))) {
                PcaKeySvrSessionPool::logging(ErrCode, svr_session->errMsg());
                if (ErrCode == PcaKeySvrSession::PKSS_SESSION_NOT_FOUND &&
                    retry_cnt++ == 0) {
                    //
                    // added by chchung 2012.10.11
                    //
                    // session user or encrypt column not found
                    // the current key server is not the owner of UserSID
                    // so retry after opening a new session
                    //
                    pc_type_open_sess_out sess_out;
                    memset(&sess_out, 0, sizeof(pc_type_open_sess_out));
                    if ((ErrCode = svr_session->openSession(
                             SessInfo.db_sid, SessInfo.instance_name,
                             SessInfo.db_name, SessInfo.client_ip,
                             SessInfo.db_user, SessInfo.os_user,
                             SessInfo.client_program, SessInfo.protocol,
                             SessInfo.user_id, SessInfo.client_mac,
                             &sess_out)) == 0) {
                        //
                        // open a new session
                        //
                        UserSID = sess_out.user_sid;
                        AuthFailCode = sess_out.auth_fail_code;
                        continue;
                    } else {
                        PcaKeySvrSessionPool::logging(ErrCode,
                                                      svr_session->errMsg());
                    }
                }
                break;
            }
            KeySvrSessionPool->returnSession(svr_session);
            if (PcaKeySvrSessionPool::traceLevel() > 1) {
                PcaKeySvrSessionPool::logging(
                    "SID[%d]:: getPriv => UserSID[%lld] EncColID[%lld] "
                    "ErrCode[%d]",
                    SID, UserSID, vkey_priv_out.enc_col_id, ErrCode);
                if (ErrCode == 0) {
                    PcaKeySvrSessionPool::logging(
                        "\nSID[%d]:: priv => kid[%lld] MaxColLen[%u] "
                        "AltThreshold[%u] maskingThreshold[%u] \n"
                        "ColType[%d] Multibyte[%d] EncPriv[%d] DecPriv[%d] "
                        "AuthFailEncPriv[%d] AuthFailDecPriv[%d] "
                        "EncNoPrivAlert[%d] DecNoPrivAlert[%d]\n"
                        "enc_audit_flag[%d],dec_audit_flag[%d],OphuekFlag[%d]\n"
                        "enc_day[%d] enc_start_time[%d] enc_start_min[%d] "
                        "enc_end_hour[%d] enc_end_min[%d] "
                        "enc_contrary_flag[%d]\n"
                        "dec_dey[%d] dec_start_time[%d] dec_start_min[%d] "
                        "dec_end_hour[%d] dec_end_min[%d] "
                        "dec_contrary_flag[%d]\n",
                        SID, vkey_priv_out.key_id, vkey_priv_out.max_col_len,
                        vkey_priv_out.dec_alt_threshold,
                        vkey_priv_out.dec_masking_threshold,
                        vkey_priv_out.col_type, vkey_priv_out.multibyte_flag,
                        vkey_priv_out.enc_priv, vkey_priv_out.dec_priv,
                        vkey_priv_out.auth_fail_enc_priv,
                        vkey_priv_out.auth_fail_dec_priv,
                        vkey_priv_out.enc_no_priv_alert,
                        vkey_priv_out.dec_no_priv_alert,
                        vkey_priv_out.enc_audit_flag,
                        vkey_priv_out.dec_audit_flag, vkey_priv_out.ophuek_flag,
                        vkey_priv_out.week_map[0], vkey_priv_out.week_map[1],
                        vkey_priv_out.week_map[2], vkey_priv_out.week_map[3],
                        vkey_priv_out.week_map[4], vkey_priv_out.week_map[5],
                        vkey_priv_out.week_map[6], vkey_priv_out.week_map[7],
                        vkey_priv_out.week_map[8], vkey_priv_out.week_map[9],
                        vkey_priv_out.week_map[10], vkey_priv_out.week_map[11]);
                }
            }

            pc_type_get_priv_out priv_out;
            memcpy(&priv_out, &vkey_priv_out.key_id, sizeof(priv_out));

            if (ErrCode) {
                //
                // in case of failure while fetching privilege,
                // in which "priv" could have an pointer to the old priv.
                // so clear it;
                //
                // priv = 0;

                if (priv) ErrCode = 0;  // it's better to reuse old privilege
            } else {
                //
                // just in case of no error in getPriv
                //
                if (priv) {
                    priv->setPrivilege(&priv_out);
                } else {
                    //
                    // get an enyption column key from the key manager newly.
                    // register it with the key hash table.
                    //
                    dgt_uint8 multi_byte_size = 0;
                    if (!strcasecmp(SessCharSet, "UTF-8"))
                        multi_byte_size = 3;
                    else
                        multi_byte_size = 2;
                    if ((ErrCode = PrivilegePool.putVKeyPriv(
                             new PcaPrivilege(vkey_priv_out.enc_col_id,
                                              &priv_out, KeyPool, IVPool,
                                              multi_byte_size, virtual_key_id),
                             &priv))) {
                        PcaKeySvrSessionPool::logging(
                            ErrCode,
                            "putPriv failed: failed to lock the privilege "
                            "pool");
                    }
                }
            }

        } else {
            //
            // in case of no available key server session, in which "priv" has
            // an pointer to the old priv
            //
            // priv = 0;
            if (priv) ErrCode = 0;  // it's better to reuse old privilege
        }
    }
    return priv;
}

dgt_sint32 PcaSession::decrypt_vkey(dgt_sint64 virtual_key_id, dgt_uint8* src,
                                    dgt_sint32 src_len, dgt_uint8* dst,
                                    dgt_uint32* dst_len, dgt_uint8 target_type,
                                    dgt_schar* name1, dgt_schar* name2,
                                    dgt_schar* name3, dgt_schar* name4,
                                    dgt_schar* name5, dgt_schar* name6,
                                    dgt_schar* name7, dgt_schar* name8,
                                    dgt_schar* name9, dgt_schar* name10) {
    ErrCode = 0;
    PcaPrivilege* priv =
        getVKeyPrivilege(virtual_key_id, PCI_VKEY_CRYPT_TYPE_DEC, target_type,
                         name1, name2, name3, name4, name5, name6, name7, name8,
                         name9, name10);  // ErrCode is set in getPrivilege
    if (priv) decrypt(priv->encColID(), src, src_len, dst, dst_len, 0, priv);
    return ErrCode == 0 ? NewSqlFlag : ErrCode;
}

dgt_sint32 PcaSession::decrypt_vkey(dgt_sint64 virtual_key_id, dgt_uint8* src,
                                    dgt_sint32 src_len, dgt_uint8** dst,
                                    dgt_uint32* dst_len, dgt_uint8 target_type,
                                    dgt_schar* name1, dgt_schar* name2,
                                    dgt_schar* name3, dgt_schar* name4,
                                    dgt_schar* name5, dgt_schar* name6,
                                    dgt_schar* name7, dgt_schar* name8,
                                    dgt_schar* name9, dgt_schar* name10) {
    ErrCode = 0;
    PcaPrivilege* priv =
        getVKeyPrivilege(virtual_key_id, PCI_VKEY_CRYPT_TYPE_DEC, target_type,
                         name1, name2, name3, name4, name5, name6, name7, name8,
                         name9, name10);  // ErrCode is set in getPrivilege

    if (priv) {
        *dst_len = 4000;
        if (OutBufferLength == 0) {
            delete OutBuffer;
            OutBuffer = new dgt_uint8[OutBufferLength = 4000];
        }
        if (src_len > 2000) {
            *dst_len = 4 * (dgt_sint32)ceil((double)(src_len + 64) / 3) + 32;
            if (*dst_len > OutBufferLength) {
                delete OutBuffer;
                OutBuffer = new dgt_uint8[OutBufferLength = *dst_len];
                if (PcaKeySvrSessionPool::traceLevel() > 2)
                    PcaKeySvrSessionPool::logging(
                        "SID[%d]:: OutBuffer[%d] replaced", SID,
                        OutBufferLength);
            }
        }
        *dst = OutBuffer;
        decrypt(priv->encColID(), src, src_len, OutBuffer, dst_len, 0, priv);
    }
    // printf("##call decrypt_vkey priv[%p]\n",priv);
    return ErrCode == 0 ? NewSqlFlag : ErrCode;
}
