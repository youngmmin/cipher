/*******************************************************************
 *   File Type          :       class declaration and definition
 *   Classes            :       PccPcfsStat
 *   Implementor        :       chchung
 *   Create Date        :       2018. 7. 17
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_PCFS_STAT_H
#define PCC_PCFS_STAT_H

#include "DgcFileStream.h"
#include "PccPcfsMsg.h"

static const dgt_schar*	DFLT_PCFS_STAT_PATH = "/var/tmp/.petra/pcfs.stat";

class PccPcfsStat : public DgcObject {
  private:
	dgt_uint16	PcfsID;
	dgt_schar	StatFilePath[1025];
	pcfst_fs_stat	Stat;
  protected:
  public:
	static const dgt_uint16 MAX_FS = 60000;

	PccPcfsStat(dgt_uint32 pcfs_id,const dgt_schar* stat_file_path=DFLT_PCFS_STAT_PATH)
		: PcfsID(pcfs_id)
	{
		strncpy(StatFilePath,stat_file_path,1024);
		memset(&Stat,0,sizeof(pcfst_fs_stat));
	} 
	virtual ~PccPcfsStat() {}
	pcfst_fs_stat* statPtr() { return &Stat; }
	dgt_sint32 putStat(pcfst_fs_stat* fs_stat = 0) throw(DgcExcept)
	{
		DgcFileStream stat_file(StatFilePath,O_CREAT|O_WRONLY);
		ATHROWnR(DgcError(SPOS,"File open failed"),-1);
		if (fs_stat == 0) fs_stat=&Stat;
		if (stat_file.seek(PcfsID*sizeof(pcfst_fs_stat),SEEK_SET) < 0) {
			ATHROWnR(DgcError(SPOS,"seek failed"),-1);
		}
		if (stat_file.sendData((dgt_uint8*)fs_stat,sizeof(pcfst_fs_stat)) < 0) {
			ATHROWnR(DgcError(SPOS,"sendData failed"),-1);
		}
		return 0;
	}
	dgt_void getStat(pcfst_fs_stat* fs_stat = 0)
	{
		if (fs_stat == 0) fs_stat = &Stat;
		memset(fs_stat,0,sizeof(pcfst_fs_stat));
		DgcFileStream stat_file(StatFilePath,O_RDONLY);
		if (EXCEPT == 0) {
			if (stat_file.seek(PcfsID*sizeof(pcfst_fs_stat),SEEK_SET) >= 0) {
				stat_file.recvData((dgt_uint8*)fs_stat,sizeof(pcfst_fs_stat));
				if (fs_stat->pid == 0 || (kill((pid_t)fs_stat->pid,0) && errno == ESRCH)) {
					// no pcfs daemon
					memset(fs_stat,0,sizeof(pcfst_fs_stat));
				}
			}
		}
		fs_stat->pcfs_id = PcfsID;
		delete EXCEPTnC;
	}
};

#endif
