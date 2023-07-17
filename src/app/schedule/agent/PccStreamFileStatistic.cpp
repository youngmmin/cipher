/*******************************************************************
 *   File Type          :       File Cipher Agent classes definition
 *   Classes            :       PccStreamFileStatistic
 *   Implementor        :       shson
 *   Create Date        :       2019. 07. 03
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccStreamFileStatistic.h"

PccStreamFileStatistic::PccStreamFileStatistic()
	: FileNodeList(FILE_NODE_HASH_SIZE)
{
	DgcSpinLock::unlock(&NodeListLock);
	FileCount = 0;
}

PccStreamFileStatistic::~PccStreamFileStatistic()
{
	PccHashNode* hnp = 0;

	FileNodeList.rewind();
	dgt_sint32 delete_cnt = 0;
	while((hnp=FileNodeList.nextNode())) {
		delete (PccStreamFile*)hnp->value();
		hnp->setValue(0);
		delete_cnt++;
	}
}

PccStreamFile* PccStreamFileStatistic::updateFileNode(
			dgt_sint64 file_id,
			dgt_sint64 dir_id,
			dgt_sint64 zone_id,
			dgt_sint64 src_file_size,
			dgt_sint64 dst_file_size,
			dgt_time   lm_time,
			const dgt_schar* src_file_name,
			const dgt_schar* dst_file_name,
			dgt_sint32 error_code,
			const dgt_schar* error_msg)
{
	for(;;) {
		PccStreamFile*	file_node = 0;
		if (DgcSpinLock::lock(&NodeListLock) == 0) {
			PccHashNode*	hnp = FileNodeList.findNode(file_id);
			if (hnp == 0) { // not found and create one
				file_node = new PccStreamFile();
				file_node->reset(file_id,
								 dir_id,
								 zone_id,
								 src_file_size,
								 dst_file_size,
								 lm_time,
								 src_file_name,
								 dst_file_name,
								 error_code,
								 error_msg);
				FileNodeList.addNode(file_id,file_node);
				FileCount++;
			} else {
				file_node = (PccStreamFile*)hnp->value();
				file_node->setSrcFileSize(src_file_size);
				file_node->setDstFileSize(dst_file_size);
				file_node->setLmTime(lm_time);
				if (error_code) {
				file_node->setErrCode(error_code);
				file_node->setErrMsg(error_msg);
				}
			}
			DgcSpinLock::unlock(&NodeListLock);
		}
		if (file_node) return file_node;
	}
	return 0;
}


PccStreamFile* PccStreamFileStatistic::findFileNode(dgt_sint64 file_id)
{
		PccStreamFile* file_node = 0;
		if (DgcSpinLock::lock(&NodeListLock) == 0) {
			PccHashNode*	hnp = FileNodeList.findNode(file_id);
			if (hnp) {
				file_node = (PccStreamFile*)hnp->value();
			}
			DgcSpinLock::unlock(&NodeListLock);
		}
		if (file_node) return file_node;
		return 0;
}

dgt_void PccStreamFileStatistic::removeFileNode(dgt_sint64 file_id)
{
	PccStreamFile* file_node = 0;
	if (DgcSpinLock::lock(&NodeListLock) == 0) {
		PccHashNode* hnp = FileNodeList.findNode(file_id);
		if (hnp) {
			file_node = (PccStreamFile*)hnp->value();
			FileNodeList.removeNode(file_node->fileId());
			delete file_node;
			hnp->setValue(0);
			FileCount--;
		}
		DgcSpinLock::unlock(&NodeListLock);
	}
}

dgt_sint32 PccStreamFileStatistic::reset()
{
#if 0
	if (DgcSpinLock::lock(&NodeListLock) == 0) {
		PccHashNode*	hnp = 0;
		FileNodeList.rewind();
		while((hnp=FileNodeList.nextNode())) {
			PccStreamFile*	file_node = (PccStreamFile*)hnp->value();
		}

		DgcSpinLock::unlock(&NodeListLock);
	}
#endif
	return 0;
}

dgt_sint32 PccStreamFileStatistic::statisticCopy(DgcMemRows* sf, dgt_sint32 file_type) 
{
	pcct_get_stream_stat_out* stream_node = 0;
	if (DgcSpinLock::lock(&NodeListLock) == 0) {
		PccStreamFile* tmp = 0;
		PccHashNode* node = 0;
		FileNodeList.rewind();
		node = FileNodeList.nextNode();
		while(node) {
			tmp = (PccStreamFile*)node->value();
			if ((file_type == 1 && tmp->errCode() == 0) ||
					(file_type == 2 && tmp->errCode()) ||
					(file_type == 3)) {
				sf->add();
				sf->next();
				stream_node = (pcct_get_stream_stat_out*)sf->data();
				stream_node->file_id = tmp->fileId();
				stream_node->dir_id = tmp->dirId();
				stream_node->enc_zone_id = tmp->zoneId();
				stream_node->in_file_size = tmp->srcFileSize();
				stream_node->out_file_size = tmp->dstFileSize();
				stream_node->lm_time = tmp->lmTime();
				strncpy(stream_node->in_file_name, tmp->srcFileName(), tmp->INIT_FILE_NAME_LEN);
				strncpy(stream_node->out_file_name, tmp->dstFileName(), tmp->INIT_FILE_NAME_LEN);//gogo
				if (tmp->errCode()) {
					stream_node->error_code = tmp->errCode();
					strncpy(stream_node->error_msg, tmp->errMsg(), PccStreamFile::MAX_ERROR_MSG);//gogo
				}
				stream_node->total_count = FileCount;
			}//(file_type == 1 && tmp->errCode() == 0) ... end
		node = FileNodeList.nextNode();
	}
		DgcSpinLock::unlock(&NodeListLock);
	}
	return 0;
}

dgt_void PccStreamFileStatistic::dump() {}
