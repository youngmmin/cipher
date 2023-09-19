/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredSessionPool
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 17
 *   Description        :       KRED session pool
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredSessionPool.h"

#include "DgcConnectionMgr.h"
#include "DgcDbProcess.h"
#include "DgcLinkInfo.h"
#include "PccAuthPrivilege.h"
#include "PccTableTypes.h"
// added by shson 2018.02.07 for debugging
#include "DgcPetraWorker.h"

pksp_type_link PccKredSessionPool::Gateway1;
pksp_type_link PccKredSessionPool::Gateway2;
pksp_type_link PccKredSessionPool::Agent;

dgt_sint32 PccKredSessionPool::getConnection(pksp_type_link* link) throw(
    DgcExcept) {
    //
    // get link info
    //
    DgcLinkInfo dblink(DgcDbProcess::db().pdb());
    pt_database_link_info* link_info = dblink.getDatabaseLinkInfo(link->name);
    if (link_info == 0) {
        ATHROWnR(DgcError(SPOS, "getDatabaseLinkInfo[%s] failed", link->name),
                 -1);
    }
    strncpy(link->ip, link_info->host, 64);
    //
    // create connection and connect
    //
    dgt_schar sql_text[1024];
    dg_sprintf(sql_text,
               "(ADDRESS=(PROTOCOL=TCP)(HOST=%s)(PORT=%u)(CONN_TIMEOUT=%u)(IN_"
               "TIMEOUT=%u)(OUT_TIMEOUT=%u)(DB_NAME=%s))",
               link_info->host, link_info->port, link_info->conn_timeout,
               link_info->in_timeout, link_info->out_timeout,
               link_info->db_name);
    link->connection = DgcConnectionMgr::conMgr().getConnection("soha");
    if (link->connection->connect(sql_text, link_info->db_name,
                                  link_info->user_name,
                                  link_info->passwd) != 0) {
        DgcExcept* e = EXCEPTnC;
        delete link->connection;
        link->connection = 0;
        RTHROWnR(e,
                 DgcError(SPOS, "connect to [%s:%u] with [%s:%s] failed",
                          link_info->host, link_info->port, link_info->db_name,
                          link_info->user_name),
                 -1);
    }
    return 0;
}

dgt_void PccKredSessionPool::initialize(DgcSession* kred_session) {
    // added by shson 2018.02.07 for debugging
    dgt_dg_sys_param* param = 0;
    dgt_sint32 LogDumpMap = 0;
    param = DgcPetraWorker::getDgParam("LOG_DUMP_MAP");
    if (param == 0) {
        delete EXCEPTnC;
    } else {
        LogDumpMap = param->val_number;
    }
    memset(&Gateway1, 0, sizeof(Gateway1));
    memset(&Gateway2, 0, sizeof(Gateway2));
    memset(&Agent, 0, sizeof(Agent));
    //
    // find agent with IP of KRED agent
    //
    pct_type_db_agent agent_row;
    memset(&agent_row, 0, sizeof(agent_row));
    dgt_schar sql_text[512];
    memset(sql_text, 0, sizeof(sql_text));
    DgcSqlStmt* sql_stmt = 0;

    DgcMemRows v_bind(1);
    v_bind.addAttr(DGC_SCHR, 65, "ip");
    v_bind.reset();
    v_bind.add();
    v_bind.next();
    memcpy(v_bind.getColPtr(1), kred_session->clientCommIP(), 65);
    v_bind.rewind();

#if 0
	dg_sprintf(sql_text, "select b.* from _dblink_soha a, pct_db_agent b where a.host='%s' and a.link_name=b.kred_link", kred_session->clientCommIP());
#else
    // dg_sprintf(sql_text, "select b.* from (select link_name from
    // pt_database_link_info where host=:1) a, pct_db_agent b where
    // b.primary_gw_link = a.link_name or b.secondary_gw_link = a.link_name or
    // b.agent_link = a.link_name");
    dg_sprintf(sql_text, "select b.* from pct_db_agent b where b.kred_link=:1");
#endif

    if (LogDumpMap == 255)
        DgcWorker::PLOG.tprintf(0, "shson sqltext[%s] clientIp [%s]\n",
                                sql_text, kred_session->clientCommIP());

    while ((sql_stmt = DgcDbProcess::db().getStmt(
                DgcDbProcess::sess(), sql_text, strlen(sql_text))) &&
           sql_stmt->execute(&v_bind, 0) >= 0) {
        dgt_uint8* tmp = 0;
        if ((tmp = sql_stmt->fetch()))
            memcpy(&agent_row, tmp, sizeof(pct_type_db_agent));
        break;
    }
    DgcExcept* e = EXCEPTnC;
    delete sql_stmt;
    if (LogDumpMap == 255)
        DgcWorker::PLOG.tprintf(
            0,
            "shson agent_row.primary_gw_link [%s] agent_row.agent_link [%s]\n",
            agent_row.primary_gw_link, agent_row.agent_link);
    if (e) {
        if (LogDumpMap == 255)
            DgcWorker::PLOG.tprintf(
                0, *e, "shson initialization for KREDAgent[%s] failed:",
                kred_session->clientCommIP());
        delete e;
    } else {
        //
        // open sessions
        //
        if (*agent_row.primary_gw_link) {
            strncpy(Gateway1.name, agent_row.primary_gw_link, 32);
            if (getConnection(&Gateway1)) {
                DgcExcept* e = EXCEPTnC;
                DgcWorker::PLOG.tprintf(0, *e, "getConnection[%s] failed:",
                                        agent_row.primary_gw_link);
                delete e;
            }
        }
        if (*agent_row.secondary_gw_link) {
            strncpy(Gateway2.name, agent_row.secondary_gw_link, 32);
            if (getConnection(&Gateway2)) {
                DgcExcept* e = EXCEPTnC;
                DgcWorker::PLOG.tprintf(0, *e, "getConnection[%s] failed:",
                                        agent_row.secondary_gw_link);
                delete e;
            }
        }
        if (*agent_row.agent_link) {
            strncpy(Agent.name, agent_row.agent_link, 32);
            if (getConnection(&Agent)) {
                DgcExcept* e = EXCEPTnC;
                DgcWorker::PLOG.tprintf(
                    0, *e, "getConnection[%s] failed:", agent_row.agent_link);
                delete e;
            }
        }
    }
#if 0
#endif
}

typedef struct {
    dgt_sint64 instance_id;
    dgt_sint64 db_id;
} db_inst_id_type;

dgt_sint64 PccKredSessionPool::getUserSID(
    pc_type_open_sess_in* uinfo, dgt_sint32* auth_fail_code) throw(DgcExcept) {
    // added by shson 2018.02.07 for debugging
    dgt_dg_sys_param* param = 0;
    dgt_sint32 LogDumpMap = 0;
    param = DgcPetraWorker::getDgParam("LOG_DUMP_MAP");
    if (param == 0) {
        delete EXCEPTnC;
    } else {
        LogDumpMap = param->val_number;
    }
    //
    // start to build up a new session user
    //
    pt_type_sess_user ps_user;
    memset(&ps_user, 0, sizeof(ps_user));

    //
    // search for instance & database
    //
    DgcSqlStmt* sql_stmt = 0;
    dgt_schar sql_text[512];
    *sql_text = 0;
    if (*uinfo->instance_name && *uinfo->db_name) {
        dg_sprintf(sql_text,
                   "select b.instance_id, b.db_id"
                   "  from pt_db_instance a, pt_db_service b, pt_database c"
                   " where upper(a.instance_name) = upper(:1)"
                   "   and a.instance_id = b.instance_id"
                   "   and b.db_id = c.db_id"
                   "   and upper(c.db_name) = upper(:2)");
    } else if (*uinfo->instance_name && *uinfo->db_name == 0) {
        dg_sprintf(sql_text,
                   "select a.instance_id, b.db_id"
                   "  from pt_db_instance a, pt_db_service (+) b"
                   " where upper(a.instance_name) = upper(:1)"
                   "   and a.instance_id = b.instance_id");
    } else if (*uinfo->instance_name == 0 && *uinfo->db_name) {
        dg_sprintf(sql_text,
                   "select b.instance_id, a.db_id"
                   "  from pt_database a, pt_db_service (+) b"
                   " where a.db_name != '' and upper(a.db_name) = upper(:2)"
                   "   and a.db_id = b.db_id");
    }
    if (*sql_text) {
        DgcMemRows db_v(2);
        db_v.addAttr(DGC_SCHR, 33, "inst_name");
        db_v.addAttr(DGC_SCHR, 33, "db_name");
        db_v.reset();
        db_v.add();
        db_v.next();
        memcpy(db_v.getColPtr(1), uinfo->instance_name, 33);
        memcpy(db_v.getColPtr(2), uinfo->db_name, 33);
        db_v.rewind();
        sql_stmt = DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text,
                                              strlen(sql_text));
        db_inst_id_type* db_svc = 0;
        if (sql_stmt && sql_stmt->execute(&db_v, 0) >= 0 &&
            (db_svc = (db_inst_id_type*)sql_stmt->fetch())) {
            ps_user.instance_id = db_svc->instance_id;
        }
        if (EXCEPT) {
            DgcExcept* e = EXCEPTnC;
            if (e->errCode() != DGC_EC_PD_NOT_FOUND) {
#if 0
                                DgcWorker::PLOG.tprintf(0, *e, "instanace[%s] & database[%s] search failed:\n", uinfo->instance_name, uinfo->db_name);
#endif
            }
            delete e;
        }
        delete sql_stmt;
        if (ps_user.instance_id == 0) {
#if 0
                        DgcWorker::PLOG.tprintf(0,"instanace[%s] & database[%s] not found.\n", uinfo->instance_name, uinfo->db_name);
#endif
        }
    }

    //
    // search for petra gateway session user with sid of database session
    //
    ptt_sess_user sess_user;
    DgcExcept* e = 0;
    memset(&sess_user, 0, sizeof(sess_user));
    if (LogDumpMap == 255)
        DgcWorker::PLOG.tprintf(
            0,
            "shson uinfo->db_sid [%lld] ps_user.instance_id [%lld] "
            "uinfo->client_ip [%s] uinfo->instance_name [%s]\n",
            uinfo->db_sid, ps_user.instance_id, uinfo->client_ip,
            uinfo->instance_name);
    if (uinfo->db_sid) {
        //
        // search in local gateway or agent first
        //
        DgcMemRows v_bind(2);
        v_bind.addAttr(DGC_UB4, 0, "db_sid");
        v_bind.addAttr(DGC_SB8, 0, "instance_id");
        v_bind.reset();
        v_bind.add();
        v_bind.next();
        memcpy(v_bind.getColPtr(1), &uinfo->db_sid, sizeof(dgt_uint32));
        memcpy(v_bind.getColPtr(2), &ps_user.instance_id, sizeof(dgt_sint64));
        v_bind.rewind();
        dg_sprintf(sql_text,
                   "select b.* from pt_sess_stat a, pt_sess_user b \
                          where a.db_sess_id1=:1 and a.psu_id=b.psu_id and b.instance_id=:2");
        if ((sql_stmt = DgcDbProcess::db().getStmt(
                 DgcDbProcess::sess(), sql_text, strlen(sql_text))) &&
            sql_stmt->execute(&v_bind, 0) >= 0) {
            dgt_uint8* tmp_row = 0;
            if ((tmp_row = sql_stmt->fetch()))
                memcpy(&sess_user, tmp_row, sizeof(sess_user));
        }
        delete EXCEPTnC;  // no need to throw an exception here
        delete sql_stmt;
        if (sess_user.psu_id == 0) {
            //
            // not found with db_sid in local.
            // search in remote gateway or agent.
            //
            pksp_type_link* link = 0;
            if ((*uinfo->client_ip == 0 ||
                 !strcasecmp(uinfo->client_ip, "127.0.0.1")) &&
                *Agent.name) {
                link = &Agent;
            } else if (*uinfo->client_ip) {
                if (!strcasecmp(uinfo->client_ip, Gateway1.ip))
                    link = &Gateway1;
                else if (!strcasecmp(uinfo->client_ip, Gateway2.ip))
                    link = &Gateway2;
                else if (!strcasecmp(uinfo->client_ip, Agent.ip))
                    link = &Agent;
            }
            DgcCliStmt* stmt = 0;
            dgt_sint32 ntry = 0;
            dgt_sint32 is_link_change =
                0;  // added by shson 2019.02.27 for #519 issue
            DgcMemRows remote_bind(2);
            remote_bind.addAttr(DGC_UB4, 0, "db_sid");
            remote_bind.addAttr(DGC_SCHR, 33, "instance_name");
            remote_bind.reset();
            remote_bind.add();
            remote_bind.next();
            memcpy(remote_bind.getColPtr(1), &uinfo->db_sid,
                   sizeof(dgt_uint32));
            memcpy(remote_bind.getColPtr(2), uinfo->instance_name, 33);
            remote_bind.rewind();
            dg_sprintf(
                sql_text,
                "select b.* from pt_sess_stat a, pt_sess_user b, pt_db_instance c \
                          where a.db_sess_id1=:1 and a.psu_id=b.psu_id and b.instance_id=c.instance_id and c.instance_name=upper(:2) ");

        RETRY_GET_CONNECTION:
            for (; link;) {
                if (link->connection == 0 && getConnection(link)) break;
                stmt = link->connection->getStmt();
                if (!stmt) break;
                if (stmt->execute(sql_text, strlen(sql_text), 0, &remote_bind) <
                    0)
                    break;
                DgcMemRows* rtn_rows = stmt->returnRows();
                if (rtn_rows && rtn_rows->next())
                    memcpy(&sess_user, rtn_rows->data(), sizeof(ptt_sess_user));
                break;
            }
            e = EXCEPTnC;
            delete stmt;
            if (e) {
                delete link->connection;
                link->connection = 0;
                DgcWorker::PLOG.tprintf(
                    0, *e, "getSessUser[%d] failed:", uinfo->db_sid);
                delete e;
                if (++ntry == 1) goto RETRY_GET_CONNECTION;
            }
            // added by shson 2018.12.20 for RAC agent environment
            // this logic decision RAC environment
            // in this case, gateway1 role is stand by agent
            // after link converting, retry connection
            if (is_link_change == 0 &&
                !strcasecmp(uinfo->client_ip, "127.0.0.1") && *Agent.name &&
                *Gateway1.name && sess_user.psu_id == 0) {
                link = &Gateway1;
                is_link_change = 1;  // added by shson 2019.02.27 for #519 issue
                ntry = 0;
                if (LogDumpMap == 255)
                    DgcWorker::PLOG.tprintf(
                        0,
                        "shson not found active agent, change stand by "
                        "agent(gateway1) [%s] \n",
                        link->name);
                goto RETRY_GET_CONNECTION;
            }  // if (strncmp(link->name ,Agent.name, sizeof(Agent.name)) == 0
               // && sess_user.psu_id == 0) end
        }      // if (sess_user.psu_id == 0) end
    }          // if (uinfo->db_sid) end

    //
    // build ps_user
    //
    if (LogDumpMap == 255)
        DgcWorker::PLOG.tprintf(
            0, "shson sess_user.psu_id [%lld] sess_user.clientip [%s] \n",
            sess_user.psu_id, sess_user.client_ip);
    if (LogDumpMap == 255 && !sess_user.psu_id)
        DgcWorker::PLOG.tprintf(0, "shson not found psu_id so be bypassed\n");
    if (sess_user.psu_id) {
        //
        // found a petra gateway session user with db_sid
        //
        if (sess_user.auth_user && *sess_user.auth_user)
            strncpy(ps_user.auth_user, sess_user.auth_user, 64);
        strncpy(ps_user.client_ip, sess_user.client_ip, 64);
#if 0
                strncpy(ps_user.db_sess_user, sess_user.db_sess_user, 32);
                strncpy(ps_user.os_user, sess_user.os_user, 32);
                strncpy(ps_user.client_program, sess_user.client_program, 128);
#else
        //
        // db_user, os_user, client_program = information gatherd by cipher
        // library
        //
        if (uinfo->db_user) strncpy(ps_user.db_sess_user, uinfo->db_user, 32);
        if (uinfo->os_user) strncpy(ps_user.os_user, uinfo->os_user, 32);
        if (uinfo->client_program)
            strncpy(ps_user.client_program, uinfo->client_program, 128);
#endif
        if (sess_user.client_mac && *sess_user.client_mac)
            strncpy(ps_user.client_mac, sess_user.client_mac, 64);
        ps_user.access_protocol = sess_user.access_protocol;
    } else {
        if (uinfo->client_ip) strncpy(ps_user.client_ip, uinfo->client_ip, 64);
        if (uinfo->db_user) strncpy(ps_user.db_sess_user, uinfo->db_user, 32);
        if (uinfo->os_user) strncpy(ps_user.os_user, uinfo->os_user, 32);
        if (uinfo->client_program)
            strncpy(ps_user.client_program, uinfo->client_program, 128);
        if (uinfo->client_mac && *uinfo->client_mac)
            strncpy(ps_user.client_mac, uinfo->client_mac, 64);
        ps_user.access_protocol = uinfo->protocol;
    }

    //
    // searching for cipher auth control
    // if auth_user is null -> Do Auth
    //
    dgt_session sess_info;
    memset(&sess_info, 0, sizeof(dgt_session));
    sess_info.user = &ps_user;

#if 0
        DgcSession      cipher_session(&sess_info);
	PccAuthPrivilege auth_priv(cipher_session);	
	dgt_sint64      ret;
        if ((ret=auth_priv.authenticate()) < 0) {
                DgcExcept*      e=EXCEPTnC;
                DgcWorker::PLOG.tprintf(0,*e,"authentication failed:\n");
                *auth_fail_code = e->errCode();
                delete e;
        } else if (ret > 0) {
                strncpy(ps_user.auth_user, auth_priv.authUser(), 64);
        }
#endif
    //
    // try to get PTU_ID for user_id, client ip, db_sess_user
    //
    dgt_sint64* ptu_id = 0;

    //
    // search for a session
    //
    DgcTableSegment* user_tab = 0;
    if ((user_tab =
             (DgcTableSegment*)DgcDbProcess::db().pdb()->segMgr()->getTable(
                 "PT_SESS_USER", DGC_SEG_TABLE,
                 DgcDbProcess::sess()->databaseUser())) == 0) {
        ATHROWnR(DgcError(SPOS, "getTable failed"), 0);
        THROWnR(DgcLdbExcept(
                    DGC_EC_PD_NOT_FOUND,
                    new DgcError(SPOS, "table[PT_SESS_USER_NEW] not found")),
                0);
    }
    user_tab->unlockShare();
    DgcIndexSegment* idx = 0;
    if ((idx = (DgcIndexSegment*)DgcDbProcess::db().pdb()->idxMgr()->getIndex(
             "PT_SESS_USER_IDX2")) == 0) {
        ATHROWnR(DgcError(SPOS, "getIndex failed"), 0);
        THROWnR(DgcLdbExcept(
                    DGC_EC_PD_NOT_FOUND,
                    new DgcError(SPOS, "index[PT_SESS_USER_IDX2] not found")),
                0);
    }
    DgcRowList rows(user_tab);
    rows.reset();
    if (idx->find((dgt_uint8*)&ps_user, rows)) {
        ATHROWnR(DgcError(SPOS, "find failed"), 0);
    }
    if (rows.next()) {
        //
        // found a session user with uinfo
        //
        return ((pt_type_sess_user*)rows.data())->psu_id;
    }

    //
    // not found and need to create a new session user
    //
    //
    // get a new session id
    //
    DgcSequence* sess_seq;
    if ((sess_seq = DgcDbProcess::db().pdb()->seqMgr()->getSequence(
             DgcDbProcess::sess()->databaseUser(), "PTS_SESS_SEQ")) == 0) {
        ATHROWnR(DgcError(SPOS, "getSequence failed"), 0);
    }
    if ((ps_user.psu_id = sess_seq->nextVal(DgcDbProcess::sess())) == 0) {
        e = EXCEPTnC;
        delete sess_seq;
        RTHROWnR(e, DgcError(SPOS, "nextVal failed"), 0);
    }
    delete sess_seq;
    //
    // try to insert a new session
    //
    rows.reset();
    if (user_tab->pinInsert(DgcDbProcess::sess(), rows, 1) != 0) {
        ATHROWnR(DgcError(SPOS, "pinInsert failed"), 0);
    }
    rows.next();
    memcpy(rows.data(), &ps_user, sizeof(ps_user));
    rows.rewind();
    if (user_tab->insertCommit(DgcDbProcess::sess(), rows) != 0) {
        e = EXCEPTnC;
        e->addErr(new DgcError(SPOS, "insertCommit failed"));
        rows.rewind();
        if (user_tab->pinRollback(rows) != 0) delete EXCEPTnC;
        if (e->errCode() == DGC_EC_PD_DUP_KEY) {
            //
            // the other same application session inserted a row right before.
            // search for it again and use it.
            //
            delete e;
            e = 0;
            rows.rewind();
            if (idx->find((dgt_uint8*)&ps_user,
                          rows)) {  // search again for psu_id
                e = EXCEPTnC;
                e->addErr(new DgcError(SPOS, "find failed"));
            } else if (rows.next()) {  // found
                return ((pt_type_sess_user*)rows.data())->psu_id;
            }
        }
        if (e) {
            RTHROWnR(e, DgcError(SPOS, "adding a new session user failed"), 0);
        }
        //
        // there's still no rows with uinfo after DGC_EC_PD_DUP_KEY.
        // this could be a situation of block corruption
        //
        THROWnR(
            DgcLdbExcept(
                DGC_EC_PD_NOT_FOUND,
                new DgcError(SPOS, "index[PT_SESS_USER_IDX2] search failed")),
            0);
    }
    DgcTableSegment* ins_user_tab = 0;
    if ((ins_user_tab =
             (DgcTableSegment*)DgcDbProcess::db().pdb()->segMgr()->getTable(
                 "PT_SESS_USER_NEW", DGC_SEG_TABLE,
                 DgcDbProcess::sess()->databaseUser())) == 0) {
        ATHROWnR(DgcError(SPOS, "getTable failed"), 0);
        THROWnR(DgcLdbExcept(
                    DGC_EC_PD_NOT_FOUND,
                    new DgcError(SPOS, "table[PT_SESS_USER_NEW] not found")),
                0);
    }
    ins_user_tab->unlockShare();
    DgcRowList ins_rows(ins_user_tab);
    ins_rows.reset();
    if (ins_user_tab->pinInsert(DgcDbProcess::sess(), ins_rows, 1) != 0) {
        delete EXCEPTnC;
    }
    ins_rows.next();
    memcpy(ins_rows.data(), &ps_user, sizeof(ps_user));
    ins_rows.rewind();
    if (ins_user_tab->insertCommit(DgcDbProcess::sess(), ins_rows) != 0) {
        ins_rows.rewind();
        if (ins_user_tab->pinRollback(ins_rows) != 0) delete EXCEPTnC;
        delete EXCEPTnC;
    }

    //
    // logging authentication hist
    //
#if 0
        pt_sess_stat sess_stat;
        memset(&sess_stat,0,sizeof(pt_sess_stat));

	sess_stat.sid=uinfo->db_sid;
	sess_stat.psu_id=ps_user.psu_id;
	sess_info.stat=&sess_stat;
	if ((*auth_fail_code == PAUC_AUTH_ERRCODE_CANCEL || *auth_fail_code == PAUC_AUTH_ERRCODE_AUTH_FAIL) && ps_user.auth_user && *ps_user.auth_user) {
		if ((auth_priv.recordHistory()) < 0) {
			DgcExcept*      e=EXCEPTnC;
        		if (e) {
                		DgcWorker::PLOG.tprintf(0,*e,"Cipher Authentication logging failed");
		                delete e;
			}	
		}
	}
#endif
    return ps_user.psu_id;
}

pt_type_sess_user* PccKredSessionPool::getSessUser(dgt_sint64 psu_id) throw(
    DgcExcept) {
    DgcTableSegment* user_tab = 0;
    if ((user_tab =
             (DgcTableSegment*)DgcDbProcess::db().pdb()->segMgr()->getTable(
                 "PT_SESS_USER", DGC_SEG_TABLE,
                 DgcDbProcess::sess()->databaseUser())) == 0) {
        ATHROWnR(DgcError(SPOS, "getTable failed"), 0);
        THROWnR(
            DgcLdbExcept(DGC_EC_PD_NOT_FOUND,
                         new DgcError(SPOS, "table[PT_SESS_USER] not found")),
            0);
    }
    user_tab->unlockShare();
    DgcIndexSegment* idx = 0;
    if ((idx = (DgcIndexSegment*)DgcDbProcess::db().pdb()->idxMgr()->getIndex(
             "PT_SESS_USER_IDX1")) == 0) {
        ATHROWnR(DgcError(SPOS, "getIndex failed"), 0);
        THROWnR(DgcLdbExcept(
                    DGC_EC_PD_NOT_FOUND,
                    new DgcError(SPOS, "index[PT_SESS_USER_IDX1] not found")),
                0);
    }
    DgcRowList rows(user_tab);
    pt_type_sess_user user_row;
    user_row.psu_id = psu_id;
    rows.reset();
    if (idx->find((dgt_uint8*)&user_row, rows)) {
        ATHROWnR(DgcError(SPOS, "find failed"), 0);
    }
    if (!rows.next()) {
        THROWnR(DgcLdbExcept(
                    DGC_EC_PD_NOT_FOUND,
                    new DgcError(SPOS, "session user[%lld] not found", psu_id)),
                0);
    }
    return (pt_type_sess_user*)rows.data();
}
