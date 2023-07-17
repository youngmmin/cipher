/*******************************************************************
 *   File Type          :       File Cipher Agent classes declaration
 *   Classes            :       PccCryptDir
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 18
 *   Description        :
 *   Modification history
 *   date                    modification
 *   180713					 add setCryptDirParams,setDirPttn,setFilePttn
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_CRYPT_DIR_POOL_H
#define PCC_CRYPT_DIR_POOL_H

#include "PccCryptDir.h"
#include "DgcWorker.h"

class PccCryptDirPool : public DgcObject {
  private:
	static const dgt_sint32	MAX_DIRS = 2048;
	PccCryptZonePool&		ZonePool;
	PccCryptSchedule&		Schedule;
	PccCryptTargetFileQueue&	FileQueue;
	PccCryptTargetFileQueue&	MigrationFileQueue;
	PccCryptDir*			CryptDirs[MAX_DIRS];
	dgt_sint32			NumDirs;
	dgt_sint32			TraceLevel;
  public:
	PccCryptDirPool(PccCryptZonePool& zone_pool,PccCryptSchedule& schedule,PccCryptTargetFileQueue& file_queue,PccCryptTargetFileQueue& migration_file_queue,dgt_sint32 trace_level);
	virtual ~PccCryptDirPool();

	dgt_sint32 setCryptDir(dgt_sint64 dir_id,dgt_sint64 zone_id,dgt_uint8 status,const dgt_schar* src_dir,const dgt_schar* dst_dir,pct_crypt_zone_dir_rule* dir_rule) throw(DgcExcept);
	dgt_sint32 dropCryptDir(dgt_sint64 dir_id) throw(DgcExcept);
	dgt_sint32 numDirs() { return NumDirs; }
	dgt_sint32 setParams(DgcBgrammer* bg) throw(DgcExcept);
	dgt_sint32 setCryptDirParams(DgcBgrammer* bg) throw(DgcExcept);
	dgt_sint32 setDirPttn(DgcBgrammer* bg) throw(DgcExcept);
	dgt_sint32 setFilePttn(DgcBgrammer* bg) throw(DgcExcept);
	dgt_sint32 allPause();
	PccCryptDir* getCryptDir(dgt_sint32 idx);
	PccCryptDir* getCryptDir(const dgt_schar* dir_path);
	PccCryptDir* getCryptDirWithDid(dgt_sint64 dir_id);
};

#endif
