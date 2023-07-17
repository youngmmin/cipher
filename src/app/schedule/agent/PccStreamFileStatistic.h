/*******************************************************************
 *   File Type          :       File Cipher Agent classes declaration
 *   Classes            :       PccStreamFileStatistic
 *   Implementor        :       shson
 *   Create Date        :       2019. 07. 03 
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/

#ifndef PCC_STREAM_FILE_STATISTIC_H
#define PCC_STREAM_FILE_STATISTIC_H

#include "PccHashTable.h"
#include "DgcSpinLock.h"
#include "PccStreamFile.h"
#include "DgcMemRows.h"
#include "PccAgentMsg.h"


class PccStreamFileStatistic : public DgcObject {
  private:
	static const dgt_uint32	FILE_NODE_HASH_SIZE = 1000;
	PccHashTable	FileNodeList;	// stream file node list
	dgt_slock	NodeListLock;	// FileNodeList lock
	dgt_sint32      FileCount;
  protected:
  public:
	PccStreamFileStatistic();
	virtual ~PccStreamFileStatistic();
	PccStreamFile* updateFileNode(
			dgt_sint64 file_id,
			dgt_sint64 dir_id,
			dgt_sint64 zone_id,
			dgt_sint64 src_file_size,
			dgt_sint64 dst_file_size,
			dgt_time   lm_time,
			const dgt_schar* src_file_name,
			const dgt_schar* dst_file_name,
			dgt_sint32 error_code,
			const dgt_schar* error_msg);

	PccStreamFile* findFileNode(dgt_sint64 file_id);
	dgt_void removeFileNode(dgt_sint64 file_id);
	dgt_sint32 reset();
	dgt_sint32 statisticCopy(DgcMemRows* tf,dgt_sint32 file_type = 0);
	dgt_void dump();

};

#endif
