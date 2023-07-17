/*******************************************************************
 *   File Type          :       File Cipher Agent classes definition
 *   Classes            :       PccCryptDirPool
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 30
 *   Description        :
 *   Modification history
 *   date                    modification
 *   180713					 modifed setparam logic by shson
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccCryptDirPool.h"


PccCryptDirPool::PccCryptDirPool(PccCryptZonePool& zone_pool,PccCryptSchedule& schedule,PccCryptTargetFileQueue& file_queue,PccCryptTargetFileQueue& migration_file_queue,dgt_sint32 trace_level)
	: ZonePool(zone_pool),Schedule(schedule),FileQueue(file_queue),MigrationFileQueue(migration_file_queue),NumDirs(0) 
{
	for (dgt_sint32 i=0; i<MAX_DIRS; i++) CryptDirs[i] = 0;
	TraceLevel = trace_level;
}

PccCryptDirPool::~PccCryptDirPool()
{
	for(dgt_sint32 i=0; i<NumDirs; i++) {
		if (CryptDirs[i]) delete CryptDirs[i];
	}
}

dgt_sint32 PccCryptDirPool::setCryptDir(dgt_sint64 dir_id,dgt_sint64 zone_id,dgt_uint8 status,const dgt_schar* src_dir,const dgt_schar* dst_dir,pct_crypt_zone_dir_rule* dir_rule) throw(DgcExcept)
{
	for(dgt_sint32 i=0; i<NumDirs; i++) {
		if (CryptDirs[i] && CryptDirs[i]->dirID() == dir_id) {
			dgt_sint32 retry = 0;
			dgt_sint32 max_retry_cnt = 10;
			dgt_sint32 set_dir_flag = 0;
			while(retry < max_retry_cnt) {
				if (CryptDirs[i]->lock() == 0) {
					if (src_dir && *src_dir) CryptDirs[i]->setSrcDir(src_dir);
					if (dst_dir && *dst_dir) CryptDirs[i]->setDstDir(dst_dir);
					if (dir_rule) CryptDirs[i]->setDirRule(dir_rule);
					CryptDirs[i]->setStatus(status);
					set_dir_flag = 1;
					CryptDirs[i]->unlock();
					break;
				}
				retry++;
				napAtick();
			}
			if (set_dir_flag == 0) {
				THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"setSrcDir failed crypt_dir[%lld]",CryptDirs[i]->dirID())),-1);
			}
			return 0;
		}
	}
	if (NumDirs < MAX_DIRS) {
		PccCryptZone* crypt_zone;
		if ((crypt_zone=ZonePool.getZoneByID(zone_id)) == 0) {
			THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"getZoneByID failed[%lld]",zone_id)),-1);
		}
		CryptDirs[NumDirs++] = new PccCryptDir(dir_id,Schedule,FileQueue,MigrationFileQueue,crypt_zone,src_dir,dst_dir,dir_rule,TraceLevel,status);
	} else {
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"reach the max dirs[%d]",NumDirs)),-1);
	}
	return 0;
}

dgt_sint32 PccCryptDirPool::dropCryptDir(dgt_sint64 dir_id) throw(DgcExcept)
{
	for(dgt_sint32 i=0; i<NumDirs; i++) {
		if (CryptDirs[i] && CryptDirs[i]->dirID() == dir_id) {
			dgt_sint32 retry = 0;
			dgt_sint32 max_retry_cnt = 10;
			PccCryptDir* delete_dir = CryptDirs[i];
			CryptDirs[i] = CryptDirs[NumDirs-1];
			CryptDirs[NumDirs-1]=0;
			NumDirs--;
			while(retry < max_retry_cnt) {
				if (delete_dir->lock() == 0) {
					delete delete_dir;
					if (TraceLevel > 10) DgcWorker::PLOG.tprintf(0,"drop crypt_dir:%lld\n",dir_id);
					return 0;
				}
				retry++;
				napAtick();
			}
			THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"dropCryptDir Failed : crypt_dir lock timeout[%lld]",dir_id)),-1);
		}
	}
	THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"dropCryptDir Failed :not found crypt_dir[%lld]",dir_id)),-1);
}

dgt_sint32 PccCryptDirPool::setParams(DgcBgrammer* bg) throw(DgcExcept)
{
	dgt_schar*	val = 0;
	dgt_sint32  param_type = 0;

	if ((val=bg->getValue("crypt_dir.id"))) param_type = 1;
	else if ((val=bg->getValue("dir_pttn.enc_job_tgt_id"))) param_type = 2;
	else if ((val=bg->getValue("file_pttn.enc_job_tgt_id"))) param_type = 3;
	if (param_type == 0) {
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"unsupported params[%s]",bg->getText())),-1);
	}
	dgt_sint32  rtn = 0;
	if (param_type == 1) rtn=setCryptDirParams(bg);
	else if (param_type == 2) rtn=setDirPttn(bg);
	else if (param_type == 3) rtn=setFilePttn(bg);
	if (rtn < 0) {
		ATHROWnR(DgcError(SPOS,"setting crypt_dir parameters failed "),rtn);
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"setting crypt_dir parameters failed ")),rtn);
	}

	return 0;
}

dgt_sint32 PccCryptDirPool::setCryptDirParams(DgcBgrammer* bg) throw(DgcExcept)
{
	dgt_schar*	val = 0;
	dgt_sint64	dir_id = 0;
	dgt_sint64	zone_id = 0;
	dgt_uint8	status = PCC_STATUS_TYPE_RUN;
	dgt_schar*	src_dir = 0;
	dgt_schar*	dst_dir = 0;
	pct_crypt_zone_dir_rule dir_rule;
	memset(&dir_rule,0,sizeof(pct_crypt_zone_dir_rule));
#ifndef WIN32
	if ((val=bg->getValue("crypt_dir.id")) && *val) dir_id = dg_strtoll(val,0,10);
	if ((val=bg->getValue("crypt_dir.zone_id")) && *val) zone_id = dg_strtoll(val,0,10);
	if ((val=bg->getValue("crypt_dir.status")) && *val) status = (dgt_uint8)dg_strtoll(val,0,10);
#else
	if ((val=bg->getValue("crypt_dir.id")) && *val) dir_id = (dgt_sint64)_strtoi64(val,0,10);
	if ((val=bg->getValue("crypt_dir.zone_id")) && *val) zone_id = (dgt_sint64)_strtoi64(val,0,10);
	if ((val=bg->getValue("crypt_dir.status")) && *val) status = (dgt_uint8)_strtoi64(val,0,10);
#endif
	src_dir=bg->getValue("crypt_dir.src_dir");
	dst_dir=bg->getValue("crypt_dir.dst_dir");
	if (dir_id == 0 || zone_id == 0) {
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"not defined directory id[%lld] or zone_id[%lld]",dir_id,zone_id)),-1);
	} else if (src_dir == 0) {
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"not defined src_dir")),-1);
	}
	if (bg->getNode("crypt_dir.dir_rule")) {
		if ((val=bg->getValue("crypt_dir.dir_rule.version")) && *val) dir_rule.version = (dgt_sint32)strtol(val,0,10);
		if ((val=bg->getValue("crypt_dir.dir_rule.sfd")) && *val) dir_rule.search_first_depth = (dgt_sint32)strtol(val,0,10);
		if ((val=bg->getValue("crypt_dir.dir_rule.sld")) && *val) dir_rule.search_last_depth = (dgt_sint32)strtol(val,0,10);
		if ((val=bg->getValue("crypt_dir.dir_rule.efd")) && *val) dir_rule.enc_first_depth = (dgt_sint32)strtol(val,0,10);
		if ((val=bg->getValue("crypt_dir.dir_rule.eld")) && *val) dir_rule.enc_last_depth = (dgt_sint32)strtol(val,0,10);
	}
	pr_debug("dir_rule version[%d] search[%d:%d] enc[%d:%d]\n",dir_rule.version,dir_rule.search_first_depth,dir_rule.search_last_depth,dir_rule.enc_first_depth,dir_rule.enc_last_depth);
	if (setCryptDir(dir_id,zone_id,status,src_dir,dst_dir,&dir_rule) < 0) {
		ATHROWnR(DgcError(SPOS,"setCryptDir failed"),-1);
	}
	return 0;
}

dgt_sint32 PccCryptDirPool::setDirPttn(DgcBgrammer* bg) throw(DgcExcept)
{
	dgt_sint64 dir_id = 0;
	dgt_schar*	val = 0;
	dgt_sint32 rtn = 0;
	dgt_schar err_string[1024];
	memset(err_string, 0, sizeof(err_string));
	if ((val=bg->getValue("dir_pttn.enc_job_tgt_id")) && *val) {
#ifndef WIN32
	dir_id = dg_strtoll(val,0,10);
#else
	dir_id = (dgt_sint64)_strtoi64(val,0,10);
#endif
	}
	PccCryptDir*   crypt_dir = getCryptDirWithDid(dir_id);
	if (crypt_dir == 0) {
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"CryptDir[%lld] not found",dir_id)),-1);
	}
	dgt_sint32 retry = 0;
	dgt_sint32 max_retry_cnt = 10;
	dgt_sint32 set_dir_flag = 0;
	while(retry < max_retry_cnt) {
		if (crypt_dir->lock() == 0) {
			rtn = crypt_dir->compileDirPttns(bg,err_string);
			crypt_dir->unlock();
			if (rtn < 0) ATHROWnR(DgcError(SPOS,"setting dir_pttn parameters failed:  %s", err_string),rtn);
			set_dir_flag = 1;
			break;
		}
		retry++;
	}
	if (set_dir_flag == 0) {
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"setting dir_pttn parameters failed:lock timeout[%lld]",dir_id)),-1);
	}
	return 0;
}

dgt_sint32 PccCryptDirPool::setFilePttn(DgcBgrammer* bg) throw(DgcExcept)
{
	dgt_sint64 dir_id = 0;
	dgt_schar*	val = 0;
	dgt_sint32 rtn = 0;
	dgt_schar err_string[1024];
	memset(err_string, 0, sizeof(err_string));
	if ((val=bg->getValue("file_pttn.enc_job_tgt_id")) && *val) {
#ifndef WIN32
	dir_id = dg_strtoll(val,0,10);
#else
	dir_id = (dgt_sint64)_strtoi64(val,0,10);
#endif
	}
	PccCryptDir*   crypt_dir = getCryptDirWithDid(dir_id);
	if (crypt_dir == 0) {
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"CryptDir[%lld] not found",dir_id)),-1);
	}
	dgt_sint32 retry = 0;
	dgt_sint32 max_retry_cnt = 10;
	dgt_sint32 set_dir_flag = 0;
	while(retry < max_retry_cnt) {
		if (crypt_dir->lock() == 0) {
			rtn = crypt_dir->compileFilePttns(bg,err_string);
			crypt_dir->unlock();
			if (rtn < 0) ATHROWnR(DgcError(SPOS,"setting dir_pttn parameters failed:  %s", err_string),rtn);
			set_dir_flag = 1;
			break;
		}
		retry++;
	}
	if (set_dir_flag == 0) {
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"setting dir_pttn parameters failed:lock timeout[%lld]",dir_id)),-1);
	}
	return 0;
}

PccCryptDir* PccCryptDirPool::getCryptDir(dgt_sint32 idx)
{
	if (idx < 0 || idx >= NumDirs) return 0;
	return CryptDirs[idx];
}

PccCryptDir* PccCryptDirPool::getCryptDir(const dgt_schar* dir_path)
{
	for(dgt_sint32 i=0; i<NumDirs; i++) {
		if (strstr(dir_path,CryptDirs[i]->srcDir())) return CryptDirs[i];
	}
	return 0;
}


PccCryptDir* PccCryptDirPool::getCryptDirWithDid(dgt_sint64 dir_id)
{
	for(dgt_sint32 i=0; i<NumDirs; i++) {
		if (CryptDirs[i]->dirID() == dir_id) return CryptDirs[i];
	}
	return 0;
}

dgt_sint32 PccCryptDirPool::allPause() 
{
	for(dgt_sint32 i=0; i<NumDirs; i++) {
		if (CryptDirs[i]) CryptDirs[i]->setStatus(PCC_STATUS_TYPE_PAUSE);
	}
	return 0;
}
