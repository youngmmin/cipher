/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredService
 *   Implementor        :       Jaehun
 *   Create Date        :       2004. 12. 21
 *   Description        :       database service
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredService.h"
#include "PccKredStmtOpenSess.h"
#include "PccKredStmtGetKey.h"
#include "PccKredStmtGetPriv.h"
#include "PccKredStmtLogRequest.h"
#include "PccKredStmtAlert.h"
#include "PccKredStmtApprove.h"
#include "PccKredStmtGetEci.h"
#include "PccKredStmtCrypt.h"
#include "PccKredStmtEncCount.h"
#include "PccKredStmtPost.h"
#include "PccKredStmtPutExtKey.h"
#include "PccKredStmtGetTrailer.h"
#include "DgcSqlParser.h"
#include "PciKeyMgrIf.h"
#include "DgcDgRepository.h"
#include "PccKredSessionPool.h"
#include "PccKredStmtGetVKeyDbPriv.h"
#include "PccKredStmtGetVKeyFilePriv.h"

#if 1 // added by chchung for sending key set for cipher agent
#include "PccKredStmtGetKeySet.h"
#endif
#if 1 // added by chchung for sending key set for cipher agent
#include "PccKredStmtGetIV.h"
#endif
#if 1 // added by shson for file log request
#include "PccKredStmtFileLogRequest.h"
#include "PccKredStmtUserFileLogRequest.h"
#endif

#include "PccKredStmtGetZoneParam.h" // added by jhpark
#include "PccKredStmtGetRegEngine.h" // added by mwpark
#include "PccKredStmtGetZoneId.h" // added by shson
#include "PccKredStmtGetRegEngineId.h" // added by shson
#include "PccKredStmtGetCryptParam.h" // added by shson

#include "PccKredStmtDetectFileLogData.h" // added by mjkim for file pattern detecting
#include "PccKredStmtDetectFileLogRequest.h" // added by mjkim for file pattern detecting
#include "PccKredStmtDetectFileGetRequest.h" // added by mjkim for file pattern detecting
#include "PccKredStmtGetRsaKey.h" // added by mwpark

dgt_sint8 PccKredService::doRequest(DgcMsgDgiSqlRq* srm) throw(DgcExcept)
{
TLOG.tprintf(2,srm,"receive a request:\n");

	if ((srm->operation() & DGC_OPF_CLOSE) != 0) {
		//
		// 1. close cursor request
		//
		CursorTable->closeCursor(srm->cursor());
		srm->setCursor(0);
	}
	if ((srm->operation() & DGC_OPF_PARSE) != 0) {	// new sql text
		//
		// 2. parse request and then get a sql stmt
		//
		if (srm->sqlLength() == 0 || srm->sqlText() == 0) {
			THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"parse request with no text")),-1);
		} 
		if (srm->cursor() > 0) {
			//
			// just release the statement associated with the cursor,
			// becasue this cursor will be reused associating with a new statement.
			//
			CursorTable->closeStmt(srm->cursor());
		}

		//
		// 2.1 create KRED statement
		//
		DgcSqlParser    sql_ps(srm->sqlText(), srm->sqlLength());
		if (sql_ps.parse() != 0) ATHROWnR(DgcError(SPOS,"parse failed"),-1);
		DgcSqlTerm*	stmt_term=sql_ps.ptree();
		if (stmt_term->tid() != DgcSqlLang::DGC_SQL_DML_CALL) {
			THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"not a call statement")),-1);
		} else {
			DgcSqlTerm*	term=stmt_term->firstChild();	// call
			term->shiftReplace(1);                          // function
			term->pullup(1);
			dgt_schar	proc_name[DGC_MAX_NAME_LEN+1];
			memset(proc_name,0,DGC_MAX_NAME_LEN+1);
			strncpy(proc_name,term->name(),term->nameLen());
			proc_name[term->nameLen()]=0;
			if (!strcasecmp(proc_name,"open_session")) {
				CurrStmt = new PccKredStmtOpenSess(DgcDbProcess::db().pdb(), &Session, 0);
			} else if (!strcasecmp(proc_name,"get_key")) {
				CurrStmt = new PccKredStmtGetKey(DgcDbProcess::db().pdb(), &Session, 0);
			} else if (!strcasecmp(proc_name,"get_priv")) {
				CurrStmt = new PccKredStmtGetPriv(DgcDbProcess::db().pdb(), &Session, 0);
			} else if (!strcasecmp(proc_name,"get_eci")) {
				CurrStmt = new PccKredStmtGetEci(DgcDbProcess::db().pdb(), &Session, 0);
			} else if (!strcasecmp(proc_name,"log_request")) {
				CurrStmt = new PccKredStmtLogRequest(DgcDbProcess::db().pdb(), &Session, 0);
			} else if (!strcasecmp(proc_name,"alert")) {
				CurrStmt = new PccKredStmtAlert(DgcDbProcess::db().pdb(), &Session, 0);
			} else if (!strcasecmp(proc_name,"approve")) {
				CurrStmt = new PccKredStmtApprove(DgcDbProcess::db().pdb(), &Session, 0);
			} else if (!strcasecmp(proc_name,"crypt")) {
				CurrStmt = new PccKredStmtCrypt(DgcDbProcess::db().pdb(), &Session, 0);
			} else if (!strcasecmp(proc_name,"enc_count")) {
				CurrStmt = new PccKredStmtEncCount(DgcDbProcess::db().pdb(), &Session, 0);
			} else if (!strcasecmp(proc_name,"post")) {
				CurrStmt = new PccKredStmtPost(DgcDbProcess::db().pdb(), &Session, 0);
#if 1 // 2015.8.8 added by chchung for sending key set for cipher agent
			} else if (!strcasecmp(proc_name,"get_key_set")) {
				CurrStmt = new PccKredStmtGetKeySet(DgcDbProcess::db().pdb(), &Session, 0);
#endif
#if 1 // 2015.8.9 added by chchung for sending external initial vector for cipher agent
			} else if (!strcasecmp(proc_name,"get_iv")) {
				CurrStmt = new PccKredStmtGetIV(DgcDbProcess::db().pdb(), &Session, 0);
#endif
#if 1 // 2016.3.4 added by mwpark for putting external key for cipher agent
			} else if (!strcasecmp(proc_name,"put_ext_key")) {
				CurrStmt = new PccKredStmtPutExtKey(DgcDbProcess::db().pdb(), &Session, 0);
#endif
#if 1 // 2016.3.15 added by mwpark for get trailer for cipher agent
			} else if (!strcasecmp(proc_name,"get_trailer")) {
				CurrStmt = new PccKredStmtGetTrailer(DgcDbProcess::db().pdb(), &Session, 0);
#endif
#if 1 // 2017.2.7 added by mwpark for file log request
			} else if (!strcasecmp(proc_name,"file_request")) {
				CurrStmt = new PccKredStmtFileLogRequest(DgcDbProcess::db().pdb(), &Session, 0);
#endif
#if 1 // 2018.6.15 added by shson for user file log request
			} else if (!strcasecmp(proc_name,"user_file_request")) {
				CurrStmt = new PccKredStmtUserFileLogRequest(DgcDbProcess::db().pdb(), &Session, 0);
#endif
#if 1 // 2017.07.06 added by jhpark for check approval privilege with virtual key
			} else if (!strcasecmp(proc_name,"get_vkey_db_priv")) {
				CurrStmt = new PccKredStmtGetVKeyDbPriv(DgcDbProcess::db().pdb(), &Session, 0);
			} else if (!strcasecmp(proc_name,"get_vkey_file_priv")) {
				CurrStmt = new PccKredStmtGetVKeyFilePriv(DgcDbProcess::db().pdb(), &Session, 0);
#endif
#if 1 // 2017.8.8 added by jhpark for file cryption api
			} else if (!strcasecmp(proc_name,"get_zone_param")) {
				CurrStmt = new PccKredStmtGetZoneParam(DgcDbProcess::db().pdb(), &Session, 0);
#endif
			} else if (!strcasecmp(proc_name,"get_reg_engine")) {
				CurrStmt = new PccKredStmtGetRegEngine(DgcDbProcess::db().pdb(), &Session, 0);
			} else if (!strcasecmp(proc_name,"get_crypt_param")) {
				CurrStmt = new PccKredStmtGetCryptParam(DgcDbProcess::db().pdb(), &Session, 0);
			} else if (!strcasecmp(proc_name,"get_zone_id")) { //added by shson 2018.06.01
				CurrStmt = new PccKredStmtGetZoneId(DgcDbProcess::db().pdb(), &Session, 0);
			} else if (!strcasecmp(proc_name,"get_reg_engine_id")) { //added by shson 2018.06.01
				CurrStmt = new PccKredStmtGetRegEngineId(DgcDbProcess::db().pdb(), &Session, 0);
			} else if (!strcasecmp(proc_name,"detect_file_data")) { //added by mjkim 2019.05.29
				CurrStmt = new PccKredStmtDetectFileLogData(DgcDbProcess::db().pdb(), &Session, 0);
			} else if (!strcasecmp(proc_name,"detect_file_request")) { //added by mjkim 2019.05.29
				CurrStmt = new PccKredStmtDetectFileLogRequest(DgcDbProcess::db().pdb(), &Session, 0);
			} else if (!strcasecmp(proc_name,"get_detect_file_request")) { //added by mjkim 2019.05.29
				CurrStmt = new PccKredStmtDetectFileGetRequest(DgcDbProcess::db().pdb(), &Session, 0);
			} else if (!strcasecmp(proc_name,"get_rsa_key")) {
                                CurrStmt = new PccKredStmtGetRsaKey(DgcDbProcess::db().pdb(), &Session, 0);
			} else {
				THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"unknown procedure[%s]",proc_name)),-1);
			}
			((PccKredStmt*)CurrStmt)->setTraceLog(&TLOG);
		}
	} else if ((srm->operation() & DGC_OPF_EXECUTE) != 0 || (srm->operation() & DGC_OPF_FETCH) != 0) {
		//
		// 3. execute or fetch with the already open cursor
		//
		if ((CurrStmt=CursorTable->getStmt(srm->cursor())) == 0) {
			ATHROWnR(DgcError(SPOS,"getStmt failed"),-1);
		}
	}
	PktStream->resetIBuf();
	//
	// 4. receive bind rows if it is.
	//
	if ((srm->operation() & DGC_OPF_BIND) != 0) {
		//
		// 4.1 receive bind row format
		//
		dgt_sint8	rtn;		// return code
		if ((rtn=MsgStream->recvMessage(10)) < 0) {
			ATHROWnR(DgcError(SPOS,"recvMessage[DGICLASS] failed"),-1);
		} else if (rtn > 0) {
			if (MsgStream->currMsg()->opi() != DGICLASS) {
				THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_MSG,
					new DgcError(SPOS,"not DGICLASS[%d]",MsgStream->currMsg()->opi())),-1);
			}
		} else {
			THROWnR(DgcDbNetExcept(DGC_EC_DN_TIMEOUT,
				new DgcError(SPOS,"timeout for bind row format[DGICLASS]")),-1);
		}
TLOG.tprintf(3,MsgStream->currMsg(),"receive a row header:\n");
		UserVarRows=new DgcMemRows(((DgcMsgDgiClass*)MsgStream->currMsg())->cutClass(),1);
		//
		// 4.2 receive bind row data
		//
		if ((rtn=MsgStream->recvMessage(10)) < 0) {
			if (UserVarRows != 0) delete UserVarRows; 
			ATHROWnR(DgcError(SPOS,"recvMessage[DGIROWS] failed"),-1);
		} else if (rtn > 0) {
			if (MsgStream->currMsg()->opi() != DGIROWS) {
				if (UserVarRows != 0) delete UserVarRows;
				THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_MSG,
					new DgcError(SPOS,"not DGIROWS[%d]",MsgStream->currMsg()->opi())),-1);
			}
TLOG.tprintf(3,MsgStream->currMsg(),"receive a row message:\n");
			if (((DgcMsgDgiRows*)MsgStream->currMsg())->decodeRows(UserVarRows) < 0) {
				if (UserVarRows != 0) delete UserVarRows;
				ATHROWnR(DgcError(SPOS,"decodeRows failed"),-1);
			}
TLOG.tprintf(4,UserVarRows,"receive a rows:\n");
		} else {
			if (UserVarRows != 0) delete UserVarRows;
			THROWnR(DgcDbNetExcept(DGC_EC_DN_TIMEOUT,new DgcError(SPOS,"timeout for DGICLASS")),-1);
		}
		PktStream->resetIBuf();
	} else {
		UserVarRows=0;
	}
	//
	// 5. execute sql statement
	//
	if ((srm->operation() & DGC_OPF_EXECUTE) != 0 && CurrStmt->execute(UserVarRows) < 0) {
		ATHROWnR(DgcError(SPOS,"execute failed"),-1);
	}
	return 0;
}


dgt_sint8 PccKredService::doResponse(DgcMsgDgiSqlRq* srm) throw(DgcExcept)
{
	//
	// 1. build and return a sql response message
	//
	DgcMsgDgiSqlRs	srs(((srm->operation() & DGC_OPF_DESC_SL) | (srm->operation() & DGC_OPF_FETCH)),srm->cursor());
	if (MsgStream->sendMessage(&srs,1,0) != 0) {
		ATHROWnR(DgcError(SPOS,"sendMessage failed"),-1);
	}
TLOG.tprintf(2,&srs,"sent a response:\n");

	if (srs.operation() != 0) {
		//
		// 2. fetch the first row
		//
		dgt_uint32	rnum=0;		// the number of fetched row
		dgt_uint8*	rdata=0;	// row data
		if ((srm->operation() & DGC_OPF_FETCH) != 0) {
 			if ((rdata=CurrStmt->fetch()) == 0) {
				if (EXCEPT == 0 || EXCEPT->errCode() == DGC_EC_PD_NOT_FOUND) {
					delete EXCEPTnC;
				} else {
					ATHROWnR(DgcError(SPOS,"fetch failed"),-1);
				}
			}
		}

		if ((srm->operation() & DGC_OPF_DESC_SL) != 0) {
			//
			// 3. build and return a fetch row header
			//
			if (CurrStmt->fetchListDef() == 0) {
				ATHROWnR(DgcError(SPOS,"fetchListDef failed"),-1);
			}
			DgcMsgDgiClass	cmsg(CurrStmt->fetchListDef());
			if (MsgStream->sendMessage(&cmsg,0,0) != 0) {
				ATHROWnR(DgcError(SPOS,"sendMessage failed"),-1);
			}
TLOG.tprintf(3,&cmsg,"sent a row header:\n");
		}

		if ((srm->operation() & DGC_OPF_FETCH) != 0) {
			DgcClass*	rh_format;
			if ((rh_format=CurrStmt->fetchListDef()) == 0) {
				ATHROWnR(DgcError(SPOS,"fetchListDef failed"),0);
			}
			DgcMsgDgiRows	rmsg(rh_format->numAttrs(),rh_format->length());
			if (MsgStream->sendMessage(&rmsg,0,0) != 0) {
				ATHROWnR(DgcError(SPOS,"sendMessage[DGIROWS] failed"),-1);
			}
			if (rdata != 0) {	// send the first row
				if (rmsg.encodeRows(++rnum,rh_format,rdata) != 0) {
					ATHROWnR(DgcError(SPOS,"encodeRows failed"),-1);
				}
			}
			while((srm->moveUnit() == 0 || rnum < srm->moveUnit()) && (rdata=CurrStmt->fetch()) != 0) {
				if (rmsg.encodeRows(++rnum,rh_format,rdata) != 0) {
					ATHROWnR(DgcError(SPOS,"encodeRows failed"),-1);
				}
			}
			DgcExcept*	e=EXCEPTnC;
			if (rmsg.encodeRows(0,rh_format,0) != 0) {
				ATHROWnR(DgcError(SPOS,"encodeRows failed"),-1);
			}
TLOG.tprintf(4,"sent %d rows.\n",rnum);
			if (e != 0) {
				if (e->errCode() == DGC_EC_PD_NOT_FOUND) {
					delete e;
				} else {
					RTHROWnR(e,DgcError(SPOS,"fetch failed"),-1);
				}
			}
		}
	}
	//
	// 4. send off the last remained packet in the output packet stream buffer
	//
	if (PktStream->setPacket() != 0) {
		ATHROWnR(DgcError(SPOS,"setPacket failed"),-1);
	}
	return 0;
}


dgt_sint32 PccKredService::run() throw(DgcExcept)
DGC_TRY_BEGIN
	if (checkTrace() != 0){
		if (ctraceLevel() > 0) {
			PktStream->setTrace(DGC_PSTDD_BOTH,TLOG.logStream()); // packet trace
		} else if (ctraceLevel() == 0) {
			PktStream->setTrace();
		}
	}
	dgt_sint8	rtn;		// return code
	DgcExcept*	e=0;		// exception
	if ((rtn=MsgStream->recvMessage()) < 0) {
		ATHROWnR(DgcError(SPOS,"recvMessage[SQL] failed"),-1);
	} else if (rtn > 0) {
		if (MsgStream->currMsg()->opi() == DGISQLRQ) {
			//
			// *****************************************
			// 	new sql request
			// *****************************************
			//
			DgcMsgDgiSqlRq*	srm=(DgcMsgDgiSqlRq*)MsgStream->currMsg();
			dgt_uint32	new_cursor=0;
			dgt_sint8	unreg_stmt_flag=1;
			CurrStmt=0;
			if (OpenFlag) {
				//
				// *****************
				// 1. do request job
				// *****************
				//
				if (doRequest(srm) != 0) {
					e=EXCEPTnC;
					e->addErr(new DgcError(SPOS,"doReuqest failed"));
				}

				//
				// ****************
				// 2. do cursor job
				// ****************
				//
				if (e == 0 && (srm->operation() & DGC_OPF_PARSE)) {
					//
					// new sql statement
					//
					if ((new_cursor=CursorTable->openCursor(CurrStmt,srm->cursor())) == 0) {
						e=EXCEPTnC;
						e->addErr(new DgcError(SPOS,"openCursor failed"));
					} else {
						unreg_stmt_flag=0;
					}
					srm->setCursor(new_cursor);
				}
			} else {
				//
				// ************************
				// 3. try to open database
				// ************************
				//
				if (openDatabase(srm->sqlLength(),srm->sqlText())) {
					e=EXCEPTnC;
					e->addErr(new DgcError(SPOS,"openDatabase failed"));
				} else {
					OpenFlag=1;
					DgcDbProcess::sess()->setDatabaseUser(Session.databaseUser());
					//
					// get/set the key stash
					//
					dgt_sint32      rtn=0;
					DgcStreamSegment*       key_stash=DgcDbProcess::db().pdb()->segMgr()->getStream("_PCS_KEY_STASH");
					if (!key_stash) {
						if ((e=EXCEPTnC)) e->addErr(new DgcError(SPOS,"getStream failed"));
						else e=new DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"_PCS_KEY_STASH not found"));
					} else if ((rtn=PCI_setKeyStash((PCT_KEY_STASH*)((dgt_uint8*)key_stash + key_stash->totalSize()))) < 0) {
						e=new DgcLdbExcept(DGC_EC_LD_STMT_ERR,new DgcError(SPOS,"%d:%s",rtn,PCI_getKmgrErrMsg()));
					}
					if (DgcDgRepository::p()->load() != 0) {
						if ((e=EXCEPTnC)) e->addErr(new DgcError(SPOS,"load failed"));
					}
					//
					// initialize KRED session pool which has gateway & agent connections
					//
					PccKredSessionPool::initialize(&Session);
				}
			}
			//
			// ******************
			// 3. do response job
			// ******************
			//
			if (e == 0 && doResponse(srm) != 0) {
				e=EXCEPTnC;
				e->addErr(new DgcError(SPOS,"doResponse failed"));
				if (new_cursor != 0 && unreg_stmt_flag == 0) {
					CursorTable->closeCursor(new_cursor);
				}
			}
			if (CurrStmt && (srm->operation() & DGC_OPF_PARSE) && unreg_stmt_flag) {
				delete CurrStmt;
				CurrStmt=0;
			}
		} else if (MsgStream->currMsg()->opi() == DGIEXT) {
			//
			// *****************************************
			//	close connection request
			// *****************************************
			//
			return 1;
		} else {
			//
			// *****************************************
			// invalid request
			// *****************************************
			//
			e=new DgcDbNetExcept(DGC_EC_DN_INVALID_MSG,
				new DgcError(SPOS,"invalid request message[%d:%d:%d]",
					MsgStream->currMsg()->tti(),MsgStream->currMsg()->opi(),MsgStream->currMsg()->seq()));
		}
	}
	if (e) {
		//
		// *****************************************************
		// return exception:
		// 	send marker -> receive marker -> send exception
		// *****************************************************
		//
TLOG.tprintf(0,*e,"start to return an exception:\n");
		DgcPktMarker*	marker=(DgcPktMarker*)PktStream->newPacket(DgcPacket::DGC_PKT_MARKER);
		if (PktStream->setPacket() != 0) {
			delete marker;
			ATHROWnR(DgcError(SPOS,"setPacket failed"),-1);
		}
		delete marker;
TLOG.tprintf(0,"sent marker.\n");

		for(;;) {
			if ((rtn=PktStream->moveNext()) < 0) {
				ATHROWnR(DgcError(SPOS,"setPacket failed"),-1);
			} else if (rtn > 0) {
				if (PktStream->icpt() == DgcPacket::DGC_PKT_MARKER) {
					PktStream->mvicdpl();
					PktStream->resetIBuf();
					break;
				}
				PktStream->mvicdpl();
				PktStream->resetIBuf();
			}
		}
TLOG.tprintf(0,"received marker.\n");

		DgcMsgDgiExt	ext(e,1);
		if (MsgStream->sendMessage(&ext) != 0) {
			ATHROWnR(DgcError(SPOS,"sendMessage failed"),-1);
		}
TLOG.tprintf(0,"sent exception.\n");

	}
	PktStream->resetIBuf();
	return 0;
DGC_TRY_RTN_END


PccKredService::PccKredService(pid_t pid,DgcCommStream* comm_stream)
	: DgcDbService(pid,comm_stream,"kred_service"), OpenFlag(0)
{
}


PccKredService::~PccKredService()
{
}
