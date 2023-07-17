/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtGetKey
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :       KRED get key statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtGetKey.h"
#include "PciKeyMgrIf.h"
#include "DgcDbProcess.h"
#include "PccTableTypes.h"
#include "PccExternalKey.h"


PccKredStmtGetKey::PccKredStmtGetKey(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term)
	: PccKredStmt(pdb, session, stmt_term), NumRtnRows(0)
{
	SelectListDef=new DgcClass("select_list",11);
        SelectListDef->addAttr(DGC_UB4,0,"enc_length");
        SelectListDef->addAttr(DGC_UB2,0,"key_size");
        SelectListDef->addAttr(DGC_UB1,0,"cipher_type");
        SelectListDef->addAttr(DGC_UB1,0,"enc_mode");
        SelectListDef->addAttr(DGC_UB1,0,"iv_type");
        SelectListDef->addAttr(DGC_UB1,0,"n2n_flag");
        SelectListDef->addAttr(DGC_UB1,0,"b64_txt_enc_flag");
        SelectListDef->addAttr(DGC_UB1,0,"enc_start_pos");
        SelectListDef->addAttr(DGC_SCHR,33,"mask_char");
        SelectListDef->addAttr(DGC_SCHR,33,"char_set");
        SelectListDef->addAttr(DGC_ACHR,64,"key");
	if (strlen(Session->clientCommIP()) == 0) {
		// beq (get local server ip)
	        struct hostent *host;
        	struct in_addr addr;
	        char hostname[512];
        	memset(hostname,0,512);
	        gethostname(hostname,512);
        	host = gethostbyname (hostname);
       		if (host) {
               		if (*host->h_addr_list) {
        	                bcopy(*host->h_addr_list, (char *) &addr, sizeof(addr));
                	        Session->setClientCommIP(inet_ntoa(addr));
	                }
		}
        }
}


PccKredStmtGetKey::~PccKredStmtGetKey()
{
}

dgt_sint32 PccKredStmtGetKey::getKeyPriv(dgt_sint64 key_id, dgt_schar* ip)
{
        dgt_schar       sql_text[512];
        DgcMemRows      v_bind_key(1);
        v_bind_key.addAttr(DGC_SB8,0,"key_id");
        v_bind_key.reset();
        v_bind_key.add();
        v_bind_key.next();
        memcpy(v_bind_key.getColPtr(1),&key_id,sizeof(dgt_sint64));
        v_bind_key.rewind();
        dg_sprintf(sql_text, "select key_id from pct_ip_key_ctrl where key_id=:1");
        DgcSqlStmt*     sql_stmt=DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text, strlen(sql_text));
        DgcExcept*      e=0;
        if (sql_stmt == 0 || sql_stmt->execute(&v_bind_key,0) < 0) {
                e=EXCEPTnC;
                delete sql_stmt;
		delete e;
		DgcWorker::PLOG.tprintf(0,"[%s] execute failed\n",sql_text);
		return 1;
        }
        dgt_sint64*   cnt=0;
        dgt_sint64    temp=0;
        if ((cnt=(dgt_sint64*)sql_stmt->fetch()) == 0) {
                e=EXCEPTnC;
		delete e;
                delete sql_stmt;
		return 1;
        } else {
		memcpy(&temp, cnt, sizeof(*cnt));
		delete sql_stmt;
		delete EXCEPTnC;
		if (temp == 0) return 1;
	}
        DgcMemRows      v_bind(2);
        v_bind.addAttr(DGC_SB8,0,"key_id");
        v_bind.addAttr(DGC_SCHR,65,"ip");
        v_bind.reset();
        v_bind.add();
        v_bind.next();
        memcpy(v_bind.getColPtr(1),&key_id,sizeof(dgt_sint64));
        memcpy(v_bind.getColPtr(2),ip,65);
        v_bind.rewind();
	memset(sql_text,0,512);
        dg_sprintf(sql_text, "select key_id from pct_ip_key_ctrl where key_id=:1 and (allow_ip_addr=:2 or allow_ip_addr='*')");
        sql_stmt=DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text, strlen(sql_text));
        e=0;
        if (sql_stmt == 0 || sql_stmt->execute(&v_bind, 0) < 0) {
                e=EXCEPTnC;
                delete sql_stmt;
		delete e;
		DgcWorker::PLOG.tprintf(0,"[%s] execute failed\n",sql_text);
		return 1;
        }
	cnt=0;
	temp=0;
        if ((cnt=(dgt_sint64*)sql_stmt->fetch()) == 0) {
                e=EXCEPTnC;
                delete sql_stmt;
		delete e;
        } else {
		memcpy(&temp, cnt, sizeof(*cnt));
		delete sql_stmt;
		delete EXCEPTnC;
		if (temp > 0) return 1;
	}

        v_bind.reset();
        v_bind.add();
        v_bind.next();
        memcpy(v_bind.getColPtr(1),&key_id,sizeof(dgt_sint64));
        memcpy(v_bind.getColPtr(2),ip,65);
        v_bind.rewind();
        memset(sql_text,0,512);
        dg_sprintf(sql_text, "select key_id from pct_ip_key_ctrl where (key_id=:1 or key_id=0) and allow_ip_addr=:2");
        sql_stmt=DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text, strlen(sql_text));
        e=0;
        if (sql_stmt == 0 || sql_stmt->execute(&v_bind, 0) < 0) {
                e=EXCEPTnC;
                delete sql_stmt;
                delete e;
                DgcWorker::PLOG.tprintf(0,"[%s] execute failed\n",sql_text);
                return 1;
        }
        cnt=0;
	temp=0;
        if ((cnt=(dgt_sint64*)sql_stmt->fetch()) == 0) {
                e=EXCEPTnC;
                delete sql_stmt;
                delete e;
        } else {
		memcpy(&temp, cnt, sizeof(*cnt));
        	delete sql_stmt;
        	delete EXCEPTnC;
		if (temp > 0) return 1;
	}

	return 0;
}


dgt_sint32 PccKredStmtGetKey::execute(DgcMemRows* mrows,dgt_sint8 delete_flag) throw(DgcLdbExcept,DgcPdbExcept)
{


	if (!mrows || !mrows->next()) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"no bind row")),-1);
        }
	defineUserVars(mrows);

	//
	// get encrypt key info
	//
	dgt_sint64	key_id = *((dgt_sint64*)mrows->data());
	dgt_schar	sql_text[512];
	DgcMemRows      v_bind(1);
        v_bind.addAttr(DGC_SB8,0,"key_id");
        v_bind.reset();
        v_bind.add();
        v_bind.next();
        memcpy(v_bind.getColPtr(1),&key_id,sizeof(dgt_sint64));
        v_bind.rewind();
	dg_sprintf(sql_text,
		"select * from pct_encrypt_key where key_id=:1");
	DgcSqlStmt*	sql_stmt=DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_text, strlen(sql_text));
	DgcExcept*	e=0;
	if (sql_stmt == 0 || sql_stmt->execute(&v_bind, 0) < 0) {
		e=EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"execute[%lld] failed.",key_id),-1);
	}
	pct_type_encrypt_key*	enc_key;
	if ((enc_key=(pct_type_encrypt_key*)sql_stmt->fetch()) == 0) {
		e=EXCEPTnC;
		delete sql_stmt;
		RTHROWnR(e,DgcError(SPOS,"fetch[%lld] failed",key_id),-1);
	}
	memset(&KeyInfo, 0, sizeof(KeyInfo));
	KeyInfo.enc_length = enc_key->enc_length;
	KeyInfo.cipher_type = enc_key->cipher_type;
	KeyInfo.key_size = enc_key->key_size;
	KeyInfo.enc_mode = enc_key->enc_mode;
	KeyInfo.iv_type = enc_key->iv_type;
	KeyInfo.n2n_flag = enc_key->n2n_flag;
	KeyInfo.b64_txt_enc_flag = enc_key->b64_txt_enc_flag;
	KeyInfo.enc_start_pos = enc_key->enc_start_pos;
	strncpy(KeyInfo.mask_char, enc_key->mask_char, 32);
	strncpy(KeyInfo.char_set, enc_key->char_set, 32);
	dgt_uint16	key_no = enc_key->key_no;

	//
	// added by mwpark
	// for bmt (key expire date check and do action)
	//
	if (enc_key->expire_action && enc_key->expire_date) { 
		dgt_uint32	curr_time;
		curr_time=dgtime(&curr_time);
		if (curr_time > enc_key->expire_date) {
			THROWnR(DgcLdbExcept(DGC_EC_PD_NOT_FOUND,new DgcError(SPOS,"encrypt key expired!!")),0);
		}
			
	}
	delete sql_stmt;

	//
	// get encrypt key
	//
	dgt_sint32	rtn=0;
	if (key_no >= 10000) {
		DgcMemRows      v_bind(1);
	        v_bind.addAttr(DGC_UB2,0,"key_no");
        	v_bind.reset();
	        v_bind.add();
        	v_bind.next();
	        memcpy(v_bind.getColPtr(1),&key_no,sizeof(dgt_uint16));
        	v_bind.rewind();
		dg_sprintf(sql_text,"select * from pct_ext_key where key_no = :1");
		DgcSqlStmt* sql_stmt = DgcDbProcess::db().getStmt(Session, sql_text, strlen(sql_text));
		DgcExcept* e=0;
		if (sql_stmt == 0 || sql_stmt->execute(&v_bind, 0) < 0) {
			e=EXCEPTnC;
			delete sql_stmt;
			RTHROWnR(e,DgcError(SPOS,"execute[%lld] failed.",key_id),-1);
		}
		pct_type_ext_key* ext_key;
		if ((ext_key=(pct_type_ext_key*)sql_stmt->fetch())) {
			PccExternalKey ek;
			ek.getKey(ext_key->key_no,ext_key->sek,ext_key->seks,KeyInfo.key_size/8,KeyInfo.key);
		}
		e=EXCEPTnC;
		delete sql_stmt;
                if (e) {
                        RTHROWnR(e,DgcError(SPOS,"fetch external key_no[%u] failed",key_no),-1);
                }
	} else {
		if ((rtn=PCI_getEncryptKey(key_no, KeyInfo.key_size/8, KeyInfo.key)) < 0) {
			THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
				new DgcError(SPOS,"getEncryptKey[%lld] failed due to %d:%s",key_id, rtn, PCI_getKmgrErrMsg())),-1);
		}
	}
	dgt_sint32 priv_flag=getKeyPriv(key_id, Session->clientCommIP());
	if (priv_flag == 0) {
                //
                // log key reject history
                //
                pct_type_key_request_hist rqst_hist;
                memset(&rqst_hist, 0, sizeof(rqst_hist));
                rqst_hist.key_id = key_id;
                rqst_hist.request_date=dgtime(&rqst_hist.request_date);
                strncpy(rqst_hist.request_ip, Session->clientCommIP(), 65);
		sprintf(rqst_hist.reserved,"[%d]", DgcDbProcess::db().pdb()->dbHeader()->productID());
                DgcTableSegment*        tab=(DgcTableSegment*)DgcDbProcess::db().pdb()->segMgr()->getTable("PCT_KEY_REJECT_HIST_TEMP");
                if (tab == 0) {
                        DgcExcept*      e=EXCEPTnC;
                        if (e) {
                                DgcWorker::PLOG.tprintf(0,*e,"getTable[PCT_KEY_REJECT_HIST_TEMP] failed:\n");
                                delete e;
                        } else {
                                DgcWorker::PLOG.tprintf(0,"Table[PCT_KEY_REJECT_HIST_TEMP] not found.\n");
                        }
                } else {
                        tab->unlockShare();
                        DgcRowList      rows(tab);
                        rows.reset();
                        if (tab->pinInsert(DgcDbProcess::sess(),rows,1) != 0) {
                                DgcExcept*      e=EXCEPTnC;
                                DgcWorker::PLOG.tprintf(0,*e,"pinInsert[PCT_KEY_REJECT_HIST_TEMP] failed:\n");
                                delete e;
                        } else {
                                rows.rewind();
                                rows.next();
                                memcpy(rows.data(), &rqst_hist, rows.rowSize());
                                rows.rewind();
                                if (tab->insertCommit(DgcDbProcess::sess(), rows) != 0) {
                                        DgcExcept*      e=EXCEPTnC;
                                        rows.rewind();
                                        if (tab->pinRollback(rows)) delete EXCEPTnC;
                                        DgcWorker::PLOG.tprintf(0,*e,"insertCommit[PCT_KEY_REJECT_HIST_TEMP] failed:\n");
                                        delete e;
                                }
                        }
                }
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                                new DgcError(SPOS,"not allowed ip[%s]-key[%lld]",Session->clientCommIP(),key_id)),-1);
		
	}
	IsExecuted=1;
	NumRtnRows=0;
	//
	// log key request history
	//
	pct_type_key_request_hist rqst_hist;
	memset(&rqst_hist, 0, sizeof(rqst_hist));
	rqst_hist.key_id = key_id;
	rqst_hist.request_date=dgtime(&rqst_hist.request_date);
	strncpy(rqst_hist.request_ip, Session->clientCommIP(), 65);
	sprintf(rqst_hist.reserved,"[%d]", DgcDbProcess::db().pdb()->dbHeader()->productID());
	DgcTableSegment*	tab=(DgcTableSegment*)DgcDbProcess::db().pdb()->segMgr()->getTable("PCT_KEY_REQUEST_HIST_TEMP");
	if (tab == 0) {
		DgcExcept*	e=EXCEPTnC;
		if (e) {
			DgcWorker::PLOG.tprintf(0,*e,"getTable[PCT_KEY_REQUEST_HIST_TEMP] failed:\n");
			delete e;
		} else {
			DgcWorker::PLOG.tprintf(0,"Table[PCT_KEY_REQUEST_HIST_TEMP] not found.\n");
		}
	} else {
		tab->unlockShare();
		DgcRowList	rows(tab);
		rows.reset();
		if (tab->pinInsert(DgcDbProcess::sess(),rows,1) != 0) {
			DgcExcept*      e=EXCEPTnC;
			DgcWorker::PLOG.tprintf(0,*e,"pinInsert[PCT_KEY_REQUEST_HIST_TEMP] failed:\n");
			delete e;
		} else {
			rows.rewind();
			rows.next();
			memcpy(rows.data(), &rqst_hist, rows.rowSize());
			rows.rewind();
			if (tab->insertCommit(DgcDbProcess::sess(), rows) != 0) {
				DgcExcept*	e=EXCEPTnC;
				rows.rewind();
				if (tab->pinRollback(rows)) delete EXCEPTnC;
				DgcWorker::PLOG.tprintf(0,*e,"insertCommit[PCT_KEY_REQUEST_HIST_TEMP] failed:\n");
				delete e;
			}
		}
	}
	return 0;
}


dgt_uint8* PccKredStmtGetKey::fetch() throw(DgcLdbExcept,DgcPdbExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"can't fetch without execution")),0);
	}
	if (NumRtnRows++ == 0) return (dgt_uint8*)&KeyInfo;
	THROWnR(DgcLdbExcept(DGC_EC_PD_NOT_FOUND,new DgcError(SPOS,"not found")),0);
	return 0;
}
