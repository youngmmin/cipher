/*******************************************************************
 *   File Type          :       class declaration and definition
 *   Classes            :       PccCipherAgentSvrSession
 *   Implementor        :       Jaehun
 *   Create Date        :       2017. 6. 29
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccCipherAgentSvrSession.h"


PccCipherAgentSvrSession::PccCipherAgentSvrSession(PccAgentCryptJobPool& job_pool, dgt_sint32 sess_id, dgt_sint32 no_sess_sleep_cnt, dgt_schar* p_ip, dgt_uint16 p_port, dgt_schar* s_ip, dgt_uint16 s_port)
	: JobPool(job_pool),SessID(sess_id),CommStream(0),PktStream(0),MsgStream(0), CursorTable(100)
{
	SkipCheckConn = 0;
	NoSessionSleepCount = no_sess_sleep_cnt?no_sess_sleep_cnt:NO_SESSION_SLEEP_COUNT;
	CurrSleepCount = 0;
	PrimaryIP = p_ip;
	PrimaryPort = p_port;
	SecondaryIP = s_ip;
	SecondaryPort = s_port;
	CurrStmt = 0;
	UserVarRows = 0;
	BrokenConnFlag = 1;
	CheckConnFlag = 0;
	StopFlag = 0;
	Session.setSessType(DGC_MSB,DGC_NUM_TYPE,(dgt_uint8*)DGC_TYPE_LENGTH,(dgt_uint8*)DGC_TYPE_STRIDE);
}


PccCipherAgentSvrSession::~PccCipherAgentSvrSession()
{
	if (MsgStream) delete MsgStream;
	if (PktStream) delete PktStream;
	if (CommStream) delete CommStream;
}


dgt_sint32 PccCipherAgentSvrSession::talkType() throw(DgcExcept)
{
	if (!MsgStream) THROWnR(DgcDbNetExcept(DGC_EC_DN_NOT_FOUND,new DgcError(SPOS,"message stream is not allocated")),-1);
	if (MsgStream->sendTypeStride()) {
		ATHROWnR(DgcError(SPOS,"sendTypeStride failed"),-1);
	}
	if (MsgStream->recvMessage(10) <= 0) {
		ATHROWnR(DgcError(SPOS,"recvMessage[ACK] failed"),-1);
		THROWnR(DgcDbNetExcept(DGC_EC_DN_TIMEOUT,new DgcError(SPOS,"timeout waiting for ACK")),-1);
	}
	DgcMessage*  msg = MsgStream->currMsg();
	if (!msg) {
		ATHROWnR(DgcError(SPOS,"message is not allocated"),-1);
		THROWnR(DgcDbNetExcept(DGC_EC_DN_NOT_FOUND,new DgcError(SPOS,"message is not allocated")),-1);
	}
	if (msg->opi() != DGIEXT) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_TIMEOUT,new DgcError(SPOS,"not DGIEXT message[%d]",msg->opi())),-1);
	}
	DgcMsgDgiExt*   ext=(DgcMsgDgiExt*)msg;
	if (ext->getExcept()->classid() != 0) {
		RTHROWnR(((DgcMsgDgiExt*)msg)->cutExcept(),DgcError(SPOS,"client returned an exception[%u] err_code[%d]",ext->getExcept()->classid(),ext->getExcept()->errCode()),-1);
	}
	MsgStream->resetIBuf();
	return 0;
}


dgt_sint32 PccCipherAgentSvrSession::makeConnection(dgt_schar* ip, dgt_uint16 port) throw(DgcExcept)
{
	if (MsgStream) delete MsgStream;
	if (PktStream) delete PktStream;
	if (CommStream) delete CommStream;
	MsgStream = 0;
	PktStream = 0;
	CommStream = 0;
	CommStream = new DgcSockClient();
	if (CommStream->connectServer(ip,port) < 0) {
		ATHROWnR(DgcError(SPOS,"connectServer[%s:%u] failed",ip,port),-1);
	}
	PktStream = new DgcPacketStream(&Session,CommStream);
	MsgStream = new DgcDgMsgStream(&Session,PktStream);
	if (talkType() < 0) ATHROWnR(DgcError(SPOS,"talkType failed"),-1);
	return 0;
}


dgt_sint32 PccCipherAgentSvrSession::connect() throw(DgcExcept)
{
	CurrSleepCount = 0;
	if (makeConnection(PrimaryIP,PrimaryPort) < 0) {
		// connect to secondary
		if (*SecondaryIP) {
			DgcExcept*  e = EXCEPTnC;
			if (e) {
				DgcWorker::PLOG.tprintf(0,*e,"agent[%lld] agent_svr_session[%d] connecServer to primary failed:\n",JobPool.agentID(),SessID);
				delete e;
			}
			if (makeConnection(SecondaryIP,SecondaryPort) < 0) {
				ATHROWnR(DgcError(SPOS,"connectServer to secondary failed."),-1);
			}
		} else {
			ATHROWnR(DgcError(SPOS,"connectServer to primary failed."),-1);
		}
	}
	BrokenConnFlag = 0;
	CheckConnFlag = 0;
	SkipCheckConn = 0;
	return 0;
}


dgt_sint32 PccCipherAgentSvrSession::doRequest(DgcMsgDgiSqlRq* srm) throw(DgcExcept)
{
	if ((srm->operation() & DGC_OPF_CLOSE) != 0) {
		// 1. close cursor request
		CursorTable.closeCursor(srm->cursor());
		srm->setCursor(0);
	}
	if ((srm->operation() & DGC_OPF_PARSE) != 0) {	// new sql text
		// 2. parse request and then get a sql stmt
		if (srm->sqlLength() == 0 || srm->sqlText() == 0) {
			THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"parse request with no text")),-1);
		}
		if (srm->cursor() > 0) {
			//
			// just release the statement associated with the cursor,
			// becasue this cursor will be reused associating with a new statement.
			//
			CursorTable.closeStmt(srm->cursor());
		}
		// 2.1 create statement
		dgt_schar	proc_name[DGC_MAX_NAME_LEN+1];
		memset(proc_name,0,DGC_MAX_NAME_LEN+1);
		strncpy(proc_name,srm->sqlText(),srm->sqlLength());
		if (!strcasecmp(proc_name,"getAgentInfo")) {
			CurrStmt = new PccGetAgentInfoStmt(JobPool,SessID);
		} else if (!strcasecmp(proc_name,"setParams")) {
			CurrStmt = new PccSetParamsStmt(JobPool);
		} else if (!strcasecmp(proc_name,"getDirEntry")) {
			CurrStmt = new PccGetDirEntryStmt(JobPool);
		} else if (!strcasecmp(proc_name,"getCryptStat")) {
			CurrStmt = new PccGetCryptStatStmt(JobPool);
		} else if (!strcasecmp(proc_name,"getDirCryptStat")) {
			CurrStmt = new PccGetDirCryptStatStmt(JobPool);
		} else if (!strcasecmp(proc_name,"dropJob")) {
			CurrStmt = new PccDropJobStmt(JobPool);
		} else if (!strcasecmp(proc_name,"cryptFile")) {
			CurrStmt = new PccCryptFileStmt(JobPool);
		} else if (!strcasecmp(proc_name,"removeFile")) {
			CurrStmt = new PccRemoveFileStmt(JobPool);
		} else if (!strcasecmp(proc_name,"getTargetList")) {
			CurrStmt = new PccGetTargetListStmt(JobPool);
		} else if (!strcasecmp(proc_name,"getRecollectCryptDir")) {
			CurrStmt = new PccRecollectCryptDirStmt(JobPool);
		} else if (!strcasecmp(proc_name,"validationFile")) {
			CurrStmt = new PccValidationFileStmt(JobPool);		
		} else {
			THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"unknown procedure[%s]",proc_name)),-1);
		}
	} else if ((srm->operation() & DGC_OPF_EXECUTE) != 0 || (srm->operation() & DGC_OPF_FETCH) != 0) {
		// 3. execute or fetch with the already open cursor
		if ((CurrStmt=CursorTable.getStmt(srm->cursor())) == 0) {
			ATHROWnR(DgcError(SPOS,"getStmt failed"),-1);
		}
	}
	resetIBuf();
	// 4. receive bind rows if it is.
	if ((srm->operation() & DGC_OPF_BIND) != 0) {
		// 4.1 receive bind row format
		dgt_sint32	rtn;
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
		UserVarRows=new DgcMemRows(((DgcMsgDgiClass*)MsgStream->currMsg())->cutClass(),1);
		// 4.2 receive bind row data
		if ((rtn=MsgStream->recvMessage(10)) < 0) {
			if (UserVarRows != 0) delete UserVarRows;
			ATHROWnR(DgcError(SPOS,"recvMessage[DGIROWS] failed"),-1);
		} else if (rtn > 0) {
			if (MsgStream->currMsg()->opi() != DGIROWS) {
				if (UserVarRows != 0) delete UserVarRows;
				THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_MSG,
					new DgcError(SPOS,"not DGIROWS[%d]",MsgStream->currMsg()->opi())),-1);
			}
			if (((DgcMsgDgiRows*)MsgStream->currMsg())->decodeRows(UserVarRows) < 0) {
				if (UserVarRows != 0) delete UserVarRows;
				ATHROWnR(DgcError(SPOS,"decodeRows failed"),-1);
			}
		} else {
			if (UserVarRows != 0) delete UserVarRows;
				THROWnR(DgcDbNetExcept(DGC_EC_DN_TIMEOUT,new DgcError(SPOS,"timeout for DGICLASS")),-1);
		}
		resetIBuf();
	} else {
		UserVarRows=0;
	}
	// 5. execute sql statement
	if ((srm->operation() & DGC_OPF_EXECUTE) != 0 && CurrStmt->execute(UserVarRows) < 0) {
		ATHROWnR(DgcError(SPOS,"execute failed"),-1);
	}
	return 0;
}

dgt_sint32 PccCipherAgentSvrSession::doResponse(DgcMsgDgiSqlRq* srm) throw(DgcExcept)
{
	// 1. build and return a sql response message
	DgcMsgDgiSqlRs	srs(((srm->operation() & DGC_OPF_DESC_SL) | (srm->operation() & DGC_OPF_FETCH)),srm->cursor());
	if (MsgStream->sendMessage(&srs,1,0) != 0) {
		ATHROWnR(DgcError(SPOS,"sendMessage failed"),-1);
	}
	if (srs.operation() != 0) {
		// 2. fetch the first row
		dgt_uint32	rnum=0;		// the number of fetched row
		dgt_uint8*	rdata=0;	// row data
		if ((srm->operation() & DGC_OPF_FETCH) != 0) {
				if ((rdata=CurrStmt->fetch()) == 0) {
				if (EXCEPT == 0 || EXCEPT->errCode() == NOT_FOUND) {
					delete EXCEPTnC;
				} else {
					ATHROWnR(DgcError(SPOS,"fetch failed"),-1);
				}
			}
		}
		if ((srm->operation() & DGC_OPF_DESC_SL) != 0) {
			// 3. build and return a fetch row header
			if (CurrStmt->fetchListDef() == 0) {
				ATHROWnR(DgcError(SPOS,"fetchListDef failed"),-1);
			}
			DgcMsgDgiClass	cmsg(CurrStmt->fetchListDef());
			if (MsgStream->sendMessage(&cmsg,0,0) != 0) {
				ATHROWnR(DgcError(SPOS,"sendMessage failed"),-1);
			}
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
			if (e != 0) {
				if (e->errCode() == NOT_FOUND) {
					delete e;
				} else {
					RTHROWnR(e,DgcError(SPOS,"fetch failed"),-1);
				}
			}
		}
	}
	// 4. send off the last remained packet in the output packet stream buffer
	if (setPacket() != 0) {
		ATHROWnR(DgcError(SPOS,"setPacket failed"),-1);
	}
	return 0;
}


dgt_void PccCipherAgentSvrSession::in() throw(DgcExcept)
{
	DgcWorker::PLOG.tprintf(0,"agent[%lld] agent_svr_session[%d] starts.\n",JobPool.agentID(),SessID);
}


dgt_sint32 PccCipherAgentSvrSession::run() throw(DgcExcept)
{
	dgt_sint8	rtn = 0;		// return code
	DgcExcept*	e = 0;		// exception
	if (StopFlag) return 1;
#if 0

	if (BrokenConnFlag) {
		dgt_sint8 TryConn = 0;
		if (CurrSleepCount == 0 || (CurrSleepCount > NoSessionSleepCount)) TryConn = 1;
		if (TryConn && connect() < 0) {
			e = EXCEPTnC;
			if (e) {
				DgcWorker::PLOG.tprintf(0,*e,"agent[%lld] agent_svr_session[%d] connect failed:\n",JobPool.agentID(),SessID);
				delete e;
			}
		}
		if (BrokenConnFlag != 0) { //when connect failed
		CurrSleepCount++;
		pr_debug("CurrSleepCount [%d]\n",CurrSleepCount);
		sleep(1);
		}
		return 0;
	}
#endif
	if ((rtn=MsgStream->recvMessage(1)) < 0) {
		e = EXCEPTnC;
		DgcWorker::PLOG.tprintf(0,*e,"agent[%lld] agent_svr_session[%d] recvMessage failed:\n",JobPool.agentID(),SessID);
		delete e;
		BrokenConnFlag = 1;
		return 0;
	} else if (rtn > 0) {
		if (MsgStream->currMsg()->opi() == DGISQLRQ) {
			// 	new sql request
			DgcMsgDgiSqlRq*	srm=(DgcMsgDgiSqlRq*)MsgStream->currMsg();
			dgt_uint32	new_cursor=0;
			dgt_sint8	unreg_stmt_flag=1;
			CurrStmt=0;
pr_debug("srm->tti() [%d], srm->opi() [%d] srm->seq() [%d], srm->operation() [%d], srm->sqlText() [%s]\n",srm->tti(),srm->opi(),srm->seq(),srm->operation(),srm->sqlText());
			// 1. do request job
			if (doRequest(srm) != 0) {
				e = EXCEPTnC;
				e->addErr(new DgcError(SPOS,"doReuqest failed"));
			}
			// 2. do cursor job
			if (e == 0 && (srm->operation() & DGC_OPF_PARSE)) {
				// new sql statement
				if ((new_cursor=CursorTable.openCursor(CurrStmt,srm->cursor())) == 0) {
					e = EXCEPTnC;
					e->addErr(new DgcError(SPOS,"openCursor failed"));
				} else {
					unreg_stmt_flag=0;
				}
				srm->setCursor(new_cursor);
			}
			// 3. do response job
			if (e == 0 && doResponse(srm) != 0) {
				e = EXCEPTnC;
				e->addErr(new DgcError(SPOS,"doResponse failed"));
				if (new_cursor != 0 && unreg_stmt_flag == 0) {
					CursorTable.closeCursor(new_cursor);
				}
			}
			if (CurrStmt && (srm->operation() & DGC_OPF_PARSE) && unreg_stmt_flag) {
				delete CurrStmt;
				CurrStmt=0;
			}
		} else if (MsgStream->currMsg()->opi() == DGIEXT) {
			// procedure server disconnected
			BrokenConnFlag = 1;
			return 0;
		} else if (CheckConnFlag && MsgStream->currMsg()->opi() == PTDGILETTER) {
			CheckConnFlag = 0;
			SkipCheckConn = 0;
			return 0;
		} else {
			// invalid request
			DgcWorker::PLOG.tprintf(0,"invalid request message[%d:%d:%d]",MsgStream->currMsg()->tti(),MsgStream->currMsg()->opi(),MsgStream->currMsg()->seq());
			BrokenConnFlag = 1;
			return 0;
		}
		if (e) {
			// return exception:
			// send marker -> receive marker -> send exception
			DgcWorker::PLOG.tprintf(0,*e,"agent[%lld] agent_svr_session[%d] exception occurred:\n",JobPool.agentID(),SessID);
			DgcPktMarker*	marker=(DgcPktMarker*)newPacket(DgcPacket::DGC_PKT_MARKER);
			if (!marker) {
				delete e;
				e = EXCEPTnC;
				if (e) {
					DgcWorker::PLOG.tprintf(0,*e,"agent[%lld] agent_svr_session[%d] newPacket failed:\n",JobPool.agentID(),SessID);
					delete e;
					BrokenConnFlag = 1;
					return 0;
				}
			}
			if (setPacket() != 0) {
				delete e;
				delete marker;
				e = EXCEPTnC;
				if (e) {
					DgcWorker::PLOG.tprintf(0,*e,"agent[%lld] agent_svr_session[%d] setPacket failed:\n",JobPool.agentID(),SessID);
					delete e;
					BrokenConnFlag = 1;
					return 0;
				}
			}
			delete marker;
			for(;;) {
				if ((rtn=moveNext()) < 0) {
					delete e;
					e = EXCEPTnC;
					if (e) {
						DgcWorker::PLOG.tprintf(0,*e,"agent[%lld] agent_svr_session[%d] moveNext failed:\n",JobPool.agentID(),SessID);
						delete e;
						BrokenConnFlag = 1;
						return 0;
					}
				} else if (rtn > 0) {
					if (icpt() == DgcPacket::DGC_PKT_MARKER) {
						mvicdpl();
						resetIBuf();
						break;
					}
					mvicdpl();
					resetIBuf();
				} else {
					break;
				}
			}
			DgcMsgDgiExt ext(e);
			if (MsgStream->sendMessage(&ext) != 0) {
				delete e;
				e = EXCEPTnC;
				if (e) {
					DgcWorker::PLOG.tprintf(0,*e,"agent[%lld] agent_svr_session[%d] sendMessage failed:\n",JobPool.agentID(),SessID);
					delete e;
					BrokenConnFlag = 1;
					return 0;
				}
			}
			delete e;
		}
	} else {
#if 0
		if (CheckConnFlag == 0 && ++SkipCheckConn > 100) {
			// check connection
			PtMsgDgiLetter check_conn(1);
			if (MsgStream->sendMessage(&check_conn) != 0) {
				delete e;
				e = EXCEPTnC;
				if (e) {
					DgcWorker::PLOG.tprintf(0,*e,"agent[%lld] agent_svr_session[%d] sendMessage failed:\n",JobPool.agentID(),SessID);
					delete e;
					BrokenConnFlag = 1;
					return 0;
				}
			}
			CheckConnFlag = 1;
		} else napAtick();
#endif
	}
	resetIBuf();

	if (EXCEPT) {
		e = EXCEPTnC;
		if (e) {
			DgcWorker::PLOG.tprintf(0,*e,"agent[%lld] agent_svr_session[%d] got an exception :\n",JobPool.agentID(),SessID);
			delete e;
			BrokenConnFlag = 1;
			return 0;
		}
	}

	return 0;
}


dgt_void PccCipherAgentSvrSession::out() throw(DgcExcept)
{
	DgcWorker::PLOG.tprintf(0,"agent[%lld] agent_svr_session[%d] ends.\n",JobPool.agentID(),SessID);
}
