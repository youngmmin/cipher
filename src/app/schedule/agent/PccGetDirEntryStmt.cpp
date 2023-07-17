/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccGetDirEntryStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2017. 7. 1
 *   Description        :       get crypt statistics statement
 *   Modification history
 *   date                    modification
 *   180713					remove dependency CryptJob by shson
--------------------------------------------------------------------

********************************************************************/
#include "PccAgentStmt.h"
#include "PccFileCryptor.h"

PccGetDirEntryStmt::PccGetDirEntryStmt(PccAgentCryptJobPool& job_pool)
	: PccAgentStmt(job_pool),DirPtr(NULL),CryptJob(0),CryptDir(0),NumEntry(0),TotalCount(0),FetchCount(0),LastFetchOffset(0)
{
	SelectListDef=new DgcClass("select_list",10);
	SelectListDef->addAttr(DGC_SB8,0,"file_id");
	SelectListDef->addAttr(DGC_SB8,0,"dir_id");
	SelectListDef->addAttr(DGC_SB8,0,"zone_id");
	SelectListDef->addAttr(DGC_SB8,0,"file_size");
	SelectListDef->addAttr(DGC_UB4,0,"last_update");
	SelectListDef->addAttr(DGC_UB1,0,"type");
	SelectListDef->addAttr(DGC_UB1,0,"encrypt_flag");
	SelectListDef->addAttr(DGC_SCHR,256,"name");
	SelectListDef->addAttr(DGC_SB8,0,"curr_offset");
	SelectListDef->addAttr(DGC_SB4,0,"total_count");
}
	
PccGetDirEntryStmt::~PccGetDirEntryStmt()
{
	if (DirPtr) closedir(DirPtr);
	if (CryptJob) CryptJob->unlockShare();
}
#if defined ( sunos5 ) || defined ( sunos5_x86 )

struct ll_dirent {
        struct dirent   entry;
        char            name_buf[256];
};

#endif

dgt_sint32 PccGetDirEntryStmt::execute(DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcExcept)
{
	if (!mrows || !mrows->next()) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"no bind row")),-1);
	}
	defineUserVars(mrows);
	pcct_dir_entry_in* dir_entry_in = (pcct_dir_entry_in*)mrows->data();
	memset(DirPath,0,1025);
	strncpy(DirPath,(dgt_schar*)dir_entry_in->dir_path,1024);
	FetchCount = dir_entry_in->fetch_count; // FetchCount: 100=encrypt agent, 101=fp agent
	

#if defined ( sunos5 ) || defined ( sunos5_x86 )
	struct ll_dirent        ll_entry;
#else
	struct dirent        ll_entry;
#endif
	struct dirent*  entry=(struct dirent*)&ll_entry;
	struct dirent*  result;
	dgt_sint32      rtn = 0;
	if ((DirPtr=opendir(DirPath)) == NULL) {
		THROWnR(DgcOsExcept(errno,new DgcError(SPOS,"opendir[%s] failed",DirPath)),-1);
	}
	dgt_sint32 curr_count = 0;
	do {
#ifndef WIN32
		if ((rtn=readdir_r(DirPtr,entry,&result)) == 0) { // success
#else
		if ((result=readdir(DirPtr)) != NULL) { // success
#endif
				if (result == NULL) break; //readdir end
#ifndef WIN32
				if (strcmp(entry->d_name,".") == 0) continue;
#else
				if (strcmp(result->d_name,".") == 0) continue;
#endif
				curr_count++;
				TotalCount++; 
				if (FetchCount == curr_count) LastFetchOffset = telldir(DirPtr); //save the last fetch file offset
				if (dir_entry_in->offset != 0 && dir_entry_in->offset == telldir(DirPtr)) curr_count = 0;  //this is offset before the last fetch 
		} else { //readdir failed
#ifndef WIN32
				TotalCount = 0;
				THROWnR(DgcOsExcept(errno,new DgcError(SPOS,"readdir_r[%s] failed",DirPath)),0);
#else
                break; //reached end stream windows
#endif
		}
	  } while(1); 
		// rest count is small than fetch count or case same TotalCount and FetchCount
		// this means reached directory end
		if (FetchCount >= curr_count || 
			TotalCount == FetchCount) LastFetchOffset = 0;
		rewinddir(DirPtr);
		if (dir_entry_in->offset != 0) seekdir(DirPtr,dir_entry_in->offset);

	IsExecuted = 1;
	return 0;
}


dgt_uint8* PccGetDirEntryStmt::fetch() throw(DgcExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"can't fetch without execution")),0);
        }
#if defined ( sunos5 ) || defined ( sunos5_x86 )
        struct ll_dirent        ll_entry;
#else
        struct dirent        ll_entry;
#endif
        struct dirent*  entry=(struct dirent*)&ll_entry;
	struct dirent*  result;
	dgt_sint32      rtn = 0;
	while(1) {
#ifndef WIN32
        if ((rtn=readdir_r(DirPtr,entry,&result)) == 0) { // success
#else
        if ((result=readdir(DirPtr)) != NULL) { // success
#endif
		if (result == NULL || NumEntry == FetchCount) {
        		THROWnR(DgcDbNetExcept(NOT_FOUND,new DgcError(SPOS,"not found")),0);
		}
#ifndef WIN32
				if (strcmp(entry->d_name,".") == 0) continue;
#else
				if (strcmp(result->d_name,".") == 0) continue;
#endif
NumEntry++;
#ifndef WIN32
		memset(&DirEntry,0,sizeof(DirEntry));
		strncpy(DirEntry.name,entry->d_name,256);
		DirEntry.curr_offset = LastFetchOffset;
		DirEntry.total_count = TotalCount;
		memset(SrcFile,0,1257);
		sprintf(SrcFile,"%s/%s",DirPath,entry->d_name);
		struct stat     fstat;
		if (stat(SrcFile,&fstat) == 0) {
			DirEntry.file_id = fstat.st_ino;
			DirEntry.file_size = fstat.st_size;
			DirEntry.last_update = fstat.st_mtime;
			DirEntry.type = S_ISDIR(fstat.st_mode) ? 1 : 2; // 1 -> direcroty, 2 -> file
#if 0
			if (S_ISREG(fstat.st_mode)) {
				dgt_sint8	rtn;
				if ((rtn=PccHeaderManager::isEncrypted(SrcFile)) < 0) delete EXCEPTnC;
				else if (rtn > 0) DirEntry.encrypt_flag = 1;
				if (CryptDir && CryptDir->isTargetFile(entry->d_name)) {
					DirEntry.dir_id = CryptDir->dirID();
					DirEntry.zone_id = CryptDir->cryptZone()->zoneID();
				}
			} else if (DirEntry.type == 1 && CryptDir && CryptDir->isTargetDir(entry->d_name)) {
				DirEntry.dir_id = CryptDir->dirID();
				DirEntry.zone_id = CryptDir->cryptZone()->zoneID();
			}
#else
			if (S_ISREG(fstat.st_mode)) {
				dgt_sint8	rtn=0;
				if ((rtn=PccHeaderManager::isEncrypted(SrcFile)) < 0) delete EXCEPTnC;
				else if (rtn > 0) {
					DirEntry.encrypt_flag = rtn;
				} 
			}
#endif
		}
#else/*{{{*/
		memset(&DirEntry,0,sizeof(DirEntry));
		strncpy(DirEntry.name,result->d_name,256);
		DirEntry.curr_offset = LastFetchOffset;
		DirEntry.total_count = TotalCount;
		memset(SrcFile,0,1257);
		sprintf(SrcFile,"%s\\%s",DirPath,result->d_name);
		struct _stati64     fstat;
                if (_stati64(SrcFile,&fstat) == 0) {
                        DirEntry.file_id = fstat.st_ino;
                        DirEntry.file_size = fstat.st_size;
                        DirEntry.last_update = fstat.st_mtime;
                        DirEntry.type = S_ISDIR(fstat.st_mode) ? 1 : 2; // 1 -> direcroty, 2 -> file
#if 0
                        if (S_ISREG(fstat.st_mode)) {
                                dgt_sint8       rtn;
                                if ((rtn=PccHeaderManager::isEncrypted(SrcFile)) < 0) delete EXCEPTnC;
                                else if (rtn > 0) DirEntry.encrypt_flag = 1;
                                if (CryptDir && CryptDir->isTargetFile(result->d_name)) {
                                        DirEntry.dir_id = CryptDir->dirID();
                                        DirEntry.zone_id = CryptDir->cryptZone()->zoneID();
                                }
                        } else if (DirEntry.type == 1 && CryptDir && CryptDir->isTargetDir(result->d_name)) {
                                DirEntry.dir_id = CryptDir->dirID();
                                DirEntry.zone_id = CryptDir->cryptZone()->zoneID();
                        }
#else
			if (S_ISREG(fstat.st_mode)) {
				dgt_sint8	rtn=0;
				if ((rtn=PccHeaderManager::isEncrypted(SrcFile)) < 0) delete EXCEPTnC;
				else if (rtn > 0) {
					DirEntry.encrypt_flag = rtn;	
				} 
			}
#endif
                } else DirEntry.type = 1;//_stati64 failed :nullity file ex)c:\Users\ALL Users
#endif/*}}}*/
		return (dgt_uint8*)&DirEntry;
	} else {
#ifndef WIN32
		NumEntry = 0;
		THROWnR(DgcOsExcept(errno,new DgcError(SPOS,"readdir_r[%s] failed",DirPath)),0);
#else
		//reached end stream in windows
#endif
	}
		break;
		} //while end
        return 0;
}
