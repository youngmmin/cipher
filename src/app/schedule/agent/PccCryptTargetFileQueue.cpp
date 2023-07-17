/*******************************************************************
 *   File Type          :       File Cipher Agent classes definition
 *   Classes            :       PccCryptTargetFile
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

#include "PccCryptTargetFileQueue.h"


PccCryptTargetFile::PccCryptTargetFile()
	: DirID(0),ZoneID(0),CryptMir(0),FileNode(0),SameFileFlag(0),Next(0)
{
	SrcFileNameLen = DstFileNameLen = INIT_FILE_NAME_LEN;
	SrcFileName = new dgt_schar[SrcFileNameLen];
	DstFileName = new dgt_schar[DstFileNameLen];
	SrcFileNamePos = 0;
	DstFileNamePos = 0;
	BackupFlag = 0;
	OutExtensionFlag = 0;
	CryptStat = 0;
	ErrCode = 0;
	ErrMsg = 0;
	InputTime = 0;
}


PccCryptTargetFile::~PccCryptTargetFile()
{
	if (SrcFileName) delete SrcFileName;
	if (DstFileName) delete DstFileName;
	if (ErrMsg) delete ErrMsg;
}


dgt_void PccCryptTargetFile::reset(
			dgt_sint64 dir_id,
			dgt_sint64 zone_id,
			PccCryptMir* crypt_mir,
			pcct_file_node* file_node,
			pcct_crypt_stat* cs,
			const dgt_schar* src_file_name,
			dgt_sint32 src_file_name_pos,
			const dgt_schar* dst_file_name,
			dgt_sint32 dst_file_name_pos,
			dgt_sint32 error_code,
			const dgt_schar* error_msg)
{
	DirID = dir_id;
	ZoneID = zone_id;
	CryptMir = crypt_mir;
	FileNode = file_node;
	CryptStat = cs;
	InputTime = dgtime(&InputTime);
	dgt_sint32 src_file_name_len = dg_strlen(src_file_name);
//pr_debug("SrcFileNameLen[%d] src_file_name_len[%d] DstFileNameLen[%d]\n",SrcFileNameLen,src_file_name_len,DstFileNameLen);
//added by shson 18.04.06
	if (ErrCode) ErrCode = 0;
	if (ErrMsg) { delete ErrMsg; ErrMsg = 0; } 
	if (error_code) setErrCode(error_code);
	if (error_msg) setErrMsg(error_msg);


	if (SrcFileNameLen < src_file_name_len) {
		delete SrcFileName;
		SrcFileNameLen = src_file_name_len + EXTRA_FILE_NAME_LEN;
		SrcFileName = new dgt_schar[SrcFileNameLen];
	}
	memset(SrcFileName,0,SrcFileNameLen);
	strcpy(SrcFileName,src_file_name);
	SrcFileNamePos = src_file_name_pos;
	if (dst_file_name && *dst_file_name) {
		dgt_sint32 dst_file_name_len = dg_strlen(dst_file_name);

		if (DstFileNameLen < dst_file_name_len) {
			delete DstFileName;
			DstFileNameLen = dst_file_name_len + EXTRA_FILE_NAME_LEN;
			DstFileName = new dgt_schar[DstFileNameLen];
		}
		memset(DstFileName,0,DstFileNameLen);
		strcpy(DstFileName,dst_file_name);
		DstFileNamePos = dst_file_name_pos;
		if (strcmp(SrcFileName,DstFileName) == 0) SameFileFlag = 1;
	} else {
		if (DstFileNameLen < src_file_name_len) {
			delete DstFileName;
			DstFileNameLen = src_file_name_len + EXTRA_FILE_NAME_LEN;
			DstFileName = new dgt_schar[DstFileNameLen];
		}
		memset(DstFileName,0,DstFileNameLen);
		strcpy(DstFileName,SrcFileName);
		DstFileNamePos = src_file_name_pos;
		SameFileFlag = 1;
	}
	Next = 0;
}


dgt_void PccCryptTargetFile::copy(PccCryptTargetFile* tf)
{
	if (!tf) return;
	reset(tf->dirID(),
			tf->zoneID(),
			tf->cryptMir(),
			tf->fileNode(),
			tf->cryptStat(),
			tf->srcFileName(),
			tf->srcFileNamePos(),
			tf->dstFileName(),
			tf->dstFileNamePos(),
			tf->errCode(),
			tf->errMsg());
	Next = tf->next();

	// set them in crypt_manager's build param function
	//BackupFlag = tf->backupFlag();
	//OutExtensionFlag = tf->outExtensionFlag();

}

#if 0
PccCryptFailFile::PccCryptFailFile()
	: ErrCode(0),ErrMsg(0)
{
	ErrMsg = new dgt_schar[MAX_ERROR_MSG];
	memset(ErrMsg, 0, MAX_ERROR_MSG);
}
#endif

PccCryptTargetFileQueue::PccCryptTargetFileQueue(dgt_sint32 num_files)
	: TargetFiles(0),First(0),Last(0),FirstFree(0),LastFree(0),NumFiles(0),FileCount(0)
{
	if (num_files == 0) num_files = MAX_TARGET_FILE;
	DgcSpinLock::unlock(&ListLock);
	initializeQueue(num_files);
}


PccCryptTargetFileQueue::~PccCryptTargetFileQueue()
{
	if (TargetFiles != &NoHeapQueue) delete[] TargetFiles;
}


dgt_sint32 PccCryptTargetFileQueue::initializeQueue(dgt_sint32 num_files)
{
	if (DgcSpinLock::lock(&ListLock) == 0) {
		if (num_files > 0) {
			if (TargetFiles && TargetFiles != &NoHeapQueue) delete[] TargetFiles;
			while(num_files > 0 && (TargetFiles=new PccCryptTargetFile[num_files]) == 0) num_files = num_files/2; // insufficient heap
		}
		if (TargetFiles == 0) { // no heap
			TargetFiles = &NoHeapQueue;
			NumFiles=1;
		} else {
			NumFiles = num_files;
			for(dgt_sint32 i=0; i<NumFiles; i++) {
				TargetFiles[i].setNext(&TargetFiles[i+1]);
			}
		}
		TargetFiles[NumFiles-1].setNext(0);

		FirstFree = &TargetFiles[0];
		LastFree = &TargetFiles[NumFiles-1];
		DgcSpinLock::unlock(&ListLock);
	} else {
		return 0;
	}
	return NumFiles;
}


dgt_sint32 PccCryptTargetFileQueue::queueCopy(DgcMemRows* tf)
{
#if 1
	pcct_target_list_out* target_info = 0;
	if (DgcSpinLock::lock(&ListLock) == 0) {
		PccCryptTargetFile* tmp = First;
		while(tmp) {
			tf->add();
			tf->next();
			target_info = (pcct_target_list_out*)tf->data();
			target_info->dir_id = tmp->dirID();
			target_info->enc_zone_id = tmp->zoneID();
			strncpy(target_info->in_file_name, tmp->srcFileName(), tmp->srcFileNameLen());
			strncpy(target_info->out_file_name, tmp->dstFileName(), tmp->dstFileNameLen());//gogo
			target_info->input_time = tmp->inputTime();
			if (tmp->errCode()) {
				target_info->error_code = tmp->errCode();
				strncpy(target_info->error_msg, tmp->errMsg(), PccCryptTargetFile::MAX_ERROR_MSG);//gogo
			}
			tmp = tmp->next();
	}
		DgcSpinLock::unlock(&ListLock);
	}
	return 0;
#endif
}

dgt_sint32 PccCryptTargetFileQueue::get(PccCryptTargetFile* tf)
{
	PccCryptTargetFile* tmp = 0;
	if (DgcSpinLock::lock(&ListLock) == 0) {
//pr_debug("get FileCount[%d] First[%p] Last[%p] FirstFree[%p] LastFree[%p]\n",FileCount,First,Last,FirstFree,LastFree);
		if ((tmp=First)) {
			if ((First=tmp->next()) == 0) First = Last = 0; // now empty
			tmp->setNext(0);
			//memcpy(tf,tmp,sizeof(PccCryptTargetFile));
			// copy target file
			if (tf) tf->copy(tmp);
			if (LastFree) {
				LastFree->setNext(tmp);
			} else {
				FirstFree = tmp; // empty free list
			}
			LastFree = tmp;
			FileCount--;
		}
		DgcSpinLock::unlock(&ListLock);
	}
	return tmp ? 1 : 0;	// 0 -> no more target file
}


dgt_sint32 PccCryptTargetFileQueue::put(
		dgt_sint64 dir_id,
		dgt_sint64 zone_id,
		PccCryptMir* crypt_mir,
		pcct_file_node* file_node,
		pcct_crypt_stat* cs,
		const dgt_schar* src_file_name,
		dgt_sint32 src_file_name_pos,
		const dgt_schar* dst_file_name,
		dgt_sint32 dst_file_name_pos,
		dgt_sint32 error_code,
		const dgt_schar* error_msg)
{
	PccCryptTargetFile* free_file = 0;
	if (DgcSpinLock::lock(&ListLock) == 0) {
//pr_debug("put FileCount[%d] First[%p] Last[%p] FirstFree[%p] LastFree[%p]\n",FileCount,First,Last,FirstFree,LastFree);
		if ((free_file=FirstFree)) {
			if ((FirstFree=free_file->next()) == 0) FirstFree = LastFree = 0; // now empty
			free_file->reset(
					dir_id,
					zone_id,
					crypt_mir,
					file_node,
					cs,
					src_file_name,
					src_file_name_pos,
					dst_file_name,
					dst_file_name_pos,
					error_code,
					error_msg);
			if (Last) {
				Last->setNext(free_file);
			} else {
				First = free_file;
			}
			Last = free_file;
			FileCount++;
		}
		DgcSpinLock::unlock(&ListLock);
	}
	return free_file ? 1 : 0; // 0 -> no more free target file which means the pool is full and caller might try again
}


dgt_void PccCryptTargetFileQueue::dump()
{

	if (DgcSpinLock::lock(&ListLock) == 0) {
		PccCryptTargetFile* tmp = First;
		printf("####NumFiles[%d] FileCount[%d]\n",NumFiles,FileCount);
		while(tmp) {
			printf("src[%s] dst[%s] dir_id[%lld] zone_id[%lld] mir[%p] file_node[%p] stat[%p]\n",
					tmp->srcFileName(),
					tmp->dstFileName(),
					tmp->dirID(),
					tmp->zoneID(),
					tmp->cryptMir(),
					tmp->fileNode(),
					tmp->cryptStat());
			if (tmp->errCode()) printf("error_code [%d] error_msg [%s]\n",tmp->errCode(),tmp->errMsg());
			tmp = tmp->next();
		}

		DgcSpinLock::unlock(&ListLock);
	}
}
