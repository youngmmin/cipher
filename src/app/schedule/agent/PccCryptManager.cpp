/*******************************************************************
 *   File Type          :       File Cipher Agent classes definition
 *   Classes            :       PccCryptManager
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 30
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccCryptManager.h"

PccCryptManager::PccCryptManager(PccAgentCryptJobPool& job_pool, PccCorePool& core_pool,dgt_sint32 manager_id, dgt_sint32 agent_mode, dgt_schar* enc_col_name, dgt_schar* header_flag, dgt_sint32 buffer_size)
	: JobPool(job_pool),
	  CorePool(core_pool),
	  SessionID(-1),
	  CryptParams(0),
	  OutFileName(0),
	  WorkStage(0),
	  StopFlag(0),
	  Cryptor(0)
{
	//SessionID = 0;
	CryptParams = new dgt_schar[MAX_PARAM_LEN];
	OutFileNameLen = PccCryptTargetFile::INIT_FILE_NAME_LEN;
	OutFileName = new dgt_schar[OutFileNameLen];
	AgentMode=agent_mode;
	EncColName=enc_col_name;
	HeaderFlag=header_flag;
	BufferSize=buffer_size;
	EncryptFlag=0;
	EncFileCnt=0;
	ManagerID=manager_id;
	TargetFileFlag = 0;
	start_flag = 0;
}


PccCryptManager::~PccCryptManager()
{
	if (CryptParams) delete CryptParams;
	if (OutFileName) delete OutFileName;
}


dgt_sint32 PccCryptManager::buildStreamParam(PccCryptTargetFile& tf, PccAgentCryptJob* curr_job)
{
	PccCryptZone*	crypt_zone = 0;
	if ((crypt_zone=curr_job->repository().zonePool().getZoneByID(tf.zoneID())) == 0) {
		ATHROWnR(DgcError(SPOS,"getZoneByID[%lld] failed",tf.zoneID()),-1);
	}
	dgt_sint32	rtn = 0;
	dgt_uint32	remain_buf_len=MAX_PARAM_LEN-1;
	memset(CryptParams,0,MAX_PARAM_LEN);
	if ((rtn=crypt_zone->buildParam(CryptParams,&remain_buf_len)) < 0) {
		ATHROWnR(DgcError(SPOS,"buildParam[zone:%lld] failed",tf.zoneID()),rtn);
	}

	if (OutFileNameLen < dg_strlen(tf.dstFileName())) {
		delete OutFileName;
		OutFileNameLen = dg_strlen(tf.dstFileName()) + PccCryptTargetFile::EXTRA_FILE_NAME_LEN;
		OutFileName = new dgt_schar[OutFileNameLen];
	}
	memset(OutFileName,0,OutFileNameLen);

	if (tf.isSameFile()) {
		if (crypt_zone->hasOutExtension()) {
			sprintf(OutFileName,"%s.%s",TargetFile.dstFileName(),crypt_zone->outExtension());
		} else {
			THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"dst file[%s] is same to src file",TargetFile.dstFileName())),-1);
		}
	} else {
		strcpy(OutFileName,TargetFile.dstFileName());
	}
	tf.setBackupFlag(crypt_zone->backupFlag());
	tf.setOutExtensionFlag(crypt_zone->hasOutExtension());
	dgt_schar*	cp = CryptParams + strlen(CryptParams);
	remain_buf_len = MAX_PARAM_LEN - remain_buf_len - 1;

	return 0;
}

dgt_sint32 PccCryptManager::buildParam(PccCryptTargetFile& tf, PccAgentCryptJob* curr_job, dgt_sint32 threads, dgt_sint32 migration_flag) // return the number of cores when success
{
	PccCryptZone*	crypt_zone = 0;
	if ((crypt_zone=curr_job->repository().zonePool().getZoneByID(tf.zoneID())) == 0) {
		ATHROWnR(DgcError(SPOS,"getZoneByID[%lld] failed",tf.zoneID()),-1);
	}
	dgt_sint32	rtn = 0;
	dgt_uint32	remain_buf_len=MAX_PARAM_LEN-1;
	memset(CryptParams,0,MAX_PARAM_LEN);
	if (AgentMode <= 1) {
		if ((rtn=crypt_zone->buildParam(CryptParams,&remain_buf_len, migration_flag)) < 0) {
			ATHROWnR(DgcError(SPOS,"buildParam[zone:%lld] failed",tf.zoneID()),rtn);
		}
	} 
	if (OutFileNameLen < dg_strlen(tf.dstFileName())) {
		delete OutFileName;
		OutFileNameLen = dg_strlen(tf.dstFileName()) + PccCryptTargetFile::EXTRA_FILE_NAME_LEN;
		OutFileName = new dgt_schar[OutFileNameLen];
	}
	memset(OutFileName,0,OutFileNameLen);
	if (migration_flag == 0) {
		if (crypt_zone->hasOutExtension()) {
			sprintf(OutFileName,"%s.%s",tf.dstFileName(),crypt_zone->outExtension());
		} else if (tf.isSameFile()) {
			// add a temporary extension ._PFC
			sprintf(OutFileName,"%s%s",tf.dstFileName(),"._PFC");
		} else {
			strcpy(OutFileName,tf.dstFileName());
		}

		tf.setBackupFlag(crypt_zone->backupFlag());
		tf.setOutExtensionFlag(crypt_zone->hasOutExtension());
	} //if (migration_flag == 0) end

	if (AgentMode <= 1) {
		dgt_schar*	cp = CryptParams + strlen(CryptParams);
		remain_buf_len = MAX_PARAM_LEN - remain_buf_len - 1;
		if (threads > 0 &&
				(rtn=curr_job->repository().schedule().buildParam(threads,tf,cp,&remain_buf_len)) < 0) {
			ATHROWnR(DgcError(SPOS,"buildParam[Schedule] failed"),rtn);
		}
	}
	if (AgentMode > 1) {
		EncryptFlag=crypt_zone->encryptFlag();
		memset(CryptParams,0,MAX_PARAM_LEN);
		if (EncryptFlag==1) {
			sprintf(CryptParams,"%s","encrypt");
		} else {
			sprintf(CryptParams,"%s","decrypt");
		}
	}
	return 0;
}

dgt_sint32 PccCryptManager::streamCryption(PccAgentCryptJob* curr_job) throw(DgcExcept)
{
	WorkStage = 5;
	dgt_sint32	threads = 0;
	DgcExcept*	e = 0;
	threads = curr_job->repository().fileQueue().get(&TargetFile); // get a crypt target file queued by the Collector
	TargetFileFlag = threads;

	if (threads > 0) {
		TargetFile.cryptStat()->input_files--;
		WorkStage = 6;
		if ((buildStreamParam(TargetFile,curr_job)) < 0) { // build crypt parameter string,  rtn>0 => # of threads, rtn<0 => exception
			ATHROWnR(DgcError(SPOS,"buildParam failed\n"),-1);
		}

		WorkStage = 7;
		struct timeval	ct;
		gettimeofday(&ct,0);
		if (JobPool.traceLevel() > 0) {
			DgcWorker::PLOG.tprintf(0,"streamCryption : \n"
					"src[%s] dst[%s]\n"
					"parameter[%s]\n",
					TargetFile.srcFileName(),OutFileName,CryptParams);
		}

			//create Cryptor
			if (Cryptor) { 
				delete Cryptor;
				Cryptor = 0; 
			}
			Cryptor =  new PccFileCryptor(0,0,JobPool.traceLevel(),ManagerID);
			dgt_sint32 rtn = 0;
			dgt_sint32 file_rtn=0;
			struct stat file_info;
			struct passwd *user;
			if (AgentMode > 0) {
				if ((file_rtn = stat(TargetFile.srcFileName(), &file_info)) != -1) {
    					user = getpwuid(file_info.st_uid);
					Cryptor->setOsUser(user->pw_name);
    				}
			}
			 // crypting
			if ((rtn=Cryptor->crypt(SessionID,CryptParams,TargetFile.srcFileName(),OutFileName,AgentMode,EncColName,HeaderFlag,BufferSize)) < 0) {
				//
				// rtn = last_error_code
				// error_string from cryptor couldn't be contained in exception because of it's size = 1025
				//
				if (rtn < 0) {
					TargetFile.cryptStat()->crypt_errors++;
					if (JobPool.traceLevel() > 0) DgcWorker::PLOG.tprintf(0,"crypt failed [%s] : [%d:%s]\n",TargetFile.srcFileName(),rtn,Cryptor->errString());
					if (EXCEPT) {
						DgcExcept* e = EXCEPTnC;
						if (e) {
							DgcWorker::PLOG.tprintf(0,*e,"exception occured while crypt : \n");
							delete e;
						}
					}
				} //if (rtn < 0) end
				WorkStage = 10;
			} else { //if ((rtn=Cryptor->crypt(...)) < 0) else
				TargetFile.cryptStat()->output_files++;
				TargetFile.cryptStat()->output_bytes += Cryptor->outFileSize();
				//gettimeofday(&ct,0);
				//TargetFile.cryptStat()->end_time=ct.tv_sec;
				EncFileCnt++;
				if (JobPool.traceLevel() > 10) 
					DgcWorker::PLOG.tprintf(0,"[%s] files success crypt \n",TargetFile.srcFileName());
				else if ((JobPool.traceLevel() <= 10) && (EncFileCnt % 1000 == 0 || EncFileCnt == 1 || EncFileCnt % 1000 == 1)) 
					DgcWorker::PLOG.tprintf(0,"[%lld]files success crypt \n",EncFileCnt);

				// added by mwpark
				// 18.10.02
				// change file permission
				if (AgentMode > 0) {
					if (file_rtn !=1) {
						chown(OutFileName, file_info.st_uid, file_info.st_gid);
					}
				}
			} //if ((rtn=Cryptor->crypt(...)) < 0) else end

			//added by shson 2019.07.04 for stream encryption statistic
			curr_job->streamFileStatistic()->updateFileNode(
					TargetFile.fileNode()->file_id,
					TargetFile.dirID(),
					TargetFile.zoneID(),
					Cryptor->inFileSize(),
					Cryptor->outFileSize(),
					TargetFile.fileNode()->lm_time,
					TargetFile.srcFileName(),
					OutFileName,
					Cryptor->errCode(),
					Cryptor->errString()
					);
			if (JobPool.traceLevel() > 0) DgcWorker::PLOG.tprintf(0,"update statistic file: [%s]\n",TargetFile.srcFileName());

			if (Cryptor) {
				delete Cryptor;
				Cryptor = 0;
			}

		WorkStage = 10;
	} else { //empty file queue
		WorkStage = 12;
		napAtick();
	}
	WorkStage = 13;
	return 0;
}

dgt_sint32 PccCryptManager::fileCryption(PccAgentCryptJob* curr_job) throw(DgcExcept)
{
	WorkStage = 5;
	dgt_sint32	threads = 0;
	dgt_sint32	migration_flag = 0;
	DgcExcept*	e = 0;

	threads = curr_job->repository().fileQueue().get(&TargetFile); // get a crypt target file queued by the Collector
	if (threads == 0) { 
		//get migrationfilequeue
		threads = curr_job->repository().migrationFileQueue().get(&TargetFile); // get a crypt migration file queued by the Collector
		if (threads > 0) migration_flag = 1;
	}


	TargetFileFlag = threads;
	if (threads > 0) {
		TargetFile.cryptStat()->input_files--;
		WorkStage = 6;
		threads = curr_job->repository().schedule().usingCores();
		PccCores*	cores = 0;
		for(dgt_sint32 i=0; i<MAX_GET_CORE_TRY && (cores=CorePool.getCores(threads?threads:1)) == 0; i++) {
			if (threads > 1) threads--; // fail to get cores and decrease threads by 1
			napAtick();
		}
		if (JobPool.traceLevel() > 1) DgcWorker::PLOG.tprintf(0,"schedule cores : [%d] allocate cores : [%d]\n",curr_job->repository().schedule().usingCores(),cores ? cores->numCores():0);
		if (cores) {
			WorkStage = 7;

			if ((buildParam(TargetFile,curr_job,cores->numCores(), migration_flag)) < 0) { // build crypt parameter string,  rtn>0 => # of threads, rtn<0 => exception
				CorePool.returnCores(cores);
				ATHROWnR(DgcError(SPOS,"buildParam failed\n"),-1);
			}

			WorkStage = 8;
			struct timeval	ct;
			//gettimeofday(&ct,0);
			if (JobPool.traceLevel() > 1) {
				DgcWorker::PLOG.tprintf(0,"fileCryption : \n"
							"src[%s] dst[%s]\n"
							"parameter[%s]\n",
				TargetFile.srcFileName(),OutFileName,CryptParams);
			}
			//create Cryptor
			if (Cryptor) { 
				delete Cryptor;
				Cryptor = 0; 
			}
			Cryptor =  new PccFileCryptor(0,0,JobPool.traceLevel(),ManagerID);
			TargetFile.cryptStat()->used_cores += cores->numCores();
			//
			// added by mwpark 18.10.01
			// for controlling os_user(file`s owner) 
			//
			dgt_sint32 file_rtn=0;
			struct stat file_info;
			struct passwd *user;
			if (AgentMode > 0) {
				if ((file_rtn = stat(TargetFile.srcFileName(), &file_info)) != -1) {
    					user = getpwuid(file_info.st_uid);
					Cryptor->setOsUser(user->pw_name);
    				}
			}
			dgt_sint32 rtn = 0;
			 // crypting
			if ((rtn=Cryptor->crypt(SessionID,CryptParams,TargetFile.srcFileName(),OutFileName,AgentMode,EncColName,HeaderFlag,BufferSize)) < 0) {
				//
				// rtn = last_error_code
				// error_string from cryptor couldn't be contained in exception because of it's size = 1025
				//
#if 1	
				if (curr_job->repository().failFileQueue().isFull()) curr_job->repository().failFileQueue().get(0); //delete oldest node when file queue is full
				curr_job->repository().failFileQueue().put(TargetFile.dirID(),
									   TargetFile.zoneID(),
									   TargetFile.cryptMir(),
									   TargetFile.fileNode(),
									   TargetFile.cryptStat(),
									   TargetFile.srcFileName(),
									   TargetFile.srcFileNamePos(),
									   TargetFile.dstFileName(),
									   TargetFile.dstFileNamePos(),
									   rtn,
									   Cryptor->errString()); 
#endif
				TargetFile.cryptStat()->crypt_errors++;
				if (JobPool.traceLevel() > 0) DgcWorker::PLOG.tprintf(0,"crypt failed [%s] : [%d:%s]\n",TargetFile.srcFileName(),rtn,Cryptor->errString());
				if (EXCEPT) {
					DgcExcept* e = EXCEPTnC;
					if (e) {
						DgcWorker::PLOG.tprintf(0,*e,"exception occured while crypt : \n");
						delete e;
					}
				}
				WorkStage = 10;
			} else {
				TargetFile.cryptStat()->output_files++;
				TargetFile.cryptStat()->output_bytes += Cryptor->outFileSize();
				//gettimeofday(&ct,0);
				//TargetFile.cryptStat()->end_time=ct.tv_sec;
				EncFileCnt++;
				if (JobPool.traceLevel() > 0) {	
					if (EncFileCnt % 1000 == 0 || EncFileCnt == 1 || EncFileCnt % 1000 == 1) DgcWorker::PLOG.tprintf(0,"[%lld]files success crypt \n",EncFileCnt);
				}

				// added by mwpark
				// 18.10.02
				// change file permission
				if (AgentMode > 0) {
					if (file_rtn !=1) {
						chown(OutFileName, file_info.st_uid, file_info.st_gid);
					}
				}
	
			}
			if (Cryptor) {
				delete Cryptor;
				Cryptor = 0;
			}
#if 0
			// added by mwpark for performance
			// modify by shson, used_micros mean nullity files
			struct timeval	et;
			gettimeofday(&et,0);
			dgt_uint32	diff = (et.tv_sec-ct.tv_sec);
			if (diff) TargetFile.cryptStat()->used_micros += (diff*1000000 + (1000000-ct.tv_usec) + et.tv_usec)*threads;
			else TargetFile.cryptStat()->used_micros += (et.tv_usec - ct.tv_usec)*threads;
#endif
			if (WorkStage == 8) {
				WorkStage = 9;
				if (TargetFile.backupFlag()) {
					// backup the source file
					if (TargetFile.outExtensionFlag() == 0 && TargetFile.isSameFile()) {
						memset(OutFileName,0,OutFileNameLen);
						sprintf(OutFileName,"%s_PFC_ORG",TargetFile.dstFileName());
						if (rename(TargetFile.srcFileName(),OutFileName) < 0) { // rename the output file
							DgcWorker::PLOG.tprintf(0,"rename[%s] srcfile[%s] failed:%s\n",OutFileName,TargetFile.srcFileName(),strerror(errno));
							WorkStage = 10;
						}
					}
				} else {
					//
					// remove the source file
					//
	
					// remove file node
					PccCryptDir* crypt_dir = curr_job->repository().dirPool().getCryptDirWithDid(TargetFile.dirID());
					if (crypt_dir && crypt_dir->cryptMir() && TargetFile.fileNode()) {
						dgt_uint64 file_id = TargetFile.fileNode()->file_id;
						crypt_dir->cryptMir()->removeFileNode(file_id);
					}
					// remove source file
					if (unlink(TargetFile.srcFileName()) < 0) { // remove the source file
						DgcWorker::PLOG.tprintf(0,"unlink[%s] failed:%s\n",TargetFile.srcFileName(),strerror(errno));
						WorkStage = 10;
					}
					if (JobPool.traceLevel() > 0) DgcWorker::PLOG.tprintf(0,"remove src file : [%s]\n",TargetFile.srcFileName());
					TargetFile.cryptStat()->target_files--;
				}
			}
			if (WorkStage == 9 && TargetFile.outExtensionFlag() == 0 && TargetFile.isSameFile()) {
				//
				// need to rename the output file which has a extension "._PFC" only if backing up or unlinking the source file successes.
				// and create a file node for it which should inherit some attributes from the source file node.
				//
				memset(OutFileName,0,OutFileNameLen);
				sprintf(OutFileName,"%s._PFC",TargetFile.dstFileName());

				struct stat	fstat;
				if (stat(OutFileName,&fstat) == 0) {
					pcct_file_node*	out_file_node = TargetFile.cryptMir()->checkFileNode(&fstat);

					out_file_node->file_size = TargetFile.fileNode()->file_size;
					out_file_node->lm_time = TargetFile.fileNode()->lm_time;
					out_file_node->cllt_time = TargetFile.fileNode()->cllt_time;
				//	out_file_node->ctst_time = ct.tv_sec;
				//	gettimeofday(&ct,0);
				//	out_file_node->cted_time = ct.tv_sec;
					out_file_node->encrypt_flag = TargetFile.fileNode()->encrypt_flag;
					if (rename(OutFileName,TargetFile.dstFileName()) < 0) { // rename the output file
						DgcWorker::PLOG.tprintf(0,"rename[%s] failed:%s\n",OutFileName,strerror(errno));
					}
				}
			}
			WorkStage = 10;
			CorePool.returnCores(cores);
			//TargetFile.cryptStat()->end_time=dgtime((dgt_uint32*)&TargetFile.cryptStat()->end_time);
		} else { //if (core) else
			WorkStage = 11;
			while(curr_job->repository().fileQueue().put(
						TargetFile.dirID(),
						TargetFile.zoneID(),
						TargetFile.cryptMir(),
						TargetFile.fileNode(),
						TargetFile.cryptStat(),
						TargetFile.srcFileName(),
						TargetFile.srcFileNamePos(),
						TargetFile.dstFileName(),
						TargetFile.dstFileNamePos()) == 0) napAtick();
		} //if (core) end
	} else { //if (threads > 0) else 
		WorkStage = 12;
		napAtick();
	} //if (threads > 0) end
	WorkStage = 13;
	return 0;
}

dgt_void PccCryptManager::in() throw(DgcExcept)
{
	WorkStage = 1;
	pc_type_open_sess_in    sess_in;
	memset(&sess_in, 0, sizeof(sess_in));
	sess_in.db_sid = 0;
#if 0
	PcaSession*     session=PcaSessionPool::openSession(sess_in.db_sid);
	if (!session) {
		WorkStage = 2;
		THROW(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"openSession failed")));
	}
#endif
			SessionID = PcaApiSessionPool::getApiSession(sess_in.client_ip,sess_in.user_id,sess_in.client_program,sess_in.client_mac,sess_in.db_user,sess_in.os_user,sess_in.protocol);
#if 0
			SessionID= session->openSession(sess_in.db_sid, sess_in.instance_name, sess_in.db_name, sess_in.client_ip, sess_in.db_user,
			sess_in.os_user, sess_in.client_program, sess_in.protocol, sess_in.user_id, sess_in.client_mac);
#endif

	if (SessionID < 0) {
		WorkStage = 2;
		delete EXCEPTnC;
		DgcWorker::PLOG.tprintf(0,"SessionID failed \n");
		//THROW(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"openSession failed")));
	}
	WorkStage = 3;

	DgcWorker::PLOG.tprintf(0,"crypt_manager[%u] starts.\n",tid());
}


dgt_sint32 PccCryptManager::run() throw(DgcExcept)
{
	PccAgentCryptJob*	curr_job = 0;
	WorkStage = 4;
	TargetFileFlag = 0;
	for(dgt_sint32 i=0; i<JobPool.numJobs(); i++) {
		if ((curr_job=JobPool.jobByIdx(i))) {
			if (curr_job->repository().getJobType() == PCC_AGENT_TYPE_STREAM_JOB) {
				// stream cryption
				if (streamCryption(curr_job) < 0) {
					DgcExcept* e = EXCEPTnC;
					if (e) {
						DgcWorker::PLOG.tprintf(0,*e,"streamCryption failed : \n");
						delete e;
					}
				}
			} else if (curr_job->repository().schedule().isWorkingTime()) {
				if (fileCryption(curr_job) < 0)
				{
					DgcExcept *e = EXCEPTnC;
					if (e)
					{
						DgcWorker::PLOG.tprintf(0, *e, "fileCryption failed : \n");
						delete e;
					}
				}
			}
			curr_job->unlockShare();
		}
	}
	if (start_flag == 0 && TargetFileFlag ==1) start_flag = 1;
	if (start_flag == 1 && TargetFileFlag ==0) {
		//system("date");
		struct timeval	ct;
		gettimeofday(&ct,0);
		TargetFile.cryptStat()->end_time=ct.tv_sec;
		start_flag = 0;
	}
	if (WorkStage == 4 || TargetFileFlag == 0) napAtick();

	if (StopFlag) return 1;

	return 0;
}


dgt_void PccCryptManager::out() throw(DgcExcept)
{
	WorkStage = 21;
	DgcWorker::PLOG.tprintf(0,"crypt_manager[%u] ends.\n",tid());
}

