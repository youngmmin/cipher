/*******************************************************************
 *   File Type          :       class declaration and definition
 *   Classes            :       PccPcfsConfig
 *   Implementor        :       chchung
 *   Create Date        :       2018. 7. 17
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_PCFS_CONFIG_H
#define PCC_PCFS_CONFIG_H

#include "DgcBgmrList.h"

typedef struct {
	dgt_schar*	name;
	dgt_schar*	root_dir;
	dgt_schar*	mount_dir;
	dgt_schar*	device;
	dgt_schar*	auto_mount;
	dgt_schar*	param_path;
} pcfst_fs_attr_list;

static const dgt_schar* DFLT_FS_LIST_PATH = "/var/tmp/.petra/pcfs.conf";
static const dgt_schar* PCFS_DAEMON_BIN = "pcfs4lnx";
static const dgt_schar* PCFS_UMOUNT_DIR = "/usr/local/bin";
static const dgt_schar* PCFS_UMOUNT_BIN = "fusermount3";

class PccPcfsConfig : public DgcObject {
  private:
	static const dgt_uint16	MAX_FSs = 1024;
	pcfst_fs_attr_list	FsList[MAX_FSs];
	DgcBgmrList*		ParsedList;
	dgt_uint16		NumFs;
  protected:
  public:
	static const dgt_uint16 MTT_MOUNT = 1;
	static const dgt_uint16 MTT_UMOUNT = 2;

	PccPcfsConfig() : ParsedList(0),NumFs(0) { memset(&FsList[0],0,sizeof(pcfst_fs_attr_list)*MAX_FSs); } 
	virtual ~PccPcfsConfig() { delete ParsedList; }
	dgt_uint16 numFs() { return NumFs; }
	pcfst_fs_attr_list* fsAttrsByIdx(dgt_uint16 idx) { if (idx < NumFs) return &FsList[idx]; return 0; }
	dgt_sint32 parse(const dgt_schar* fs_list_path = DFLT_FS_LIST_PATH) throw(DgcExcept)
	{
		if (ParsedList) {
			delete ParsedList;
			memset(&FsList[0],0,sizeof(pcfst_fs_attr_list)*MAX_FSs);
			NumFs = 0;
		}
		ParsedList = new DgcBgmrList(fs_list_path);
		ATHROWnR(DgcError(SPOS,"parse[%s] failed",fs_list_path),-1);
		DgcBgrammer*    bg = 0;
		dgt_schar* val = 0;
		while((bg=ParsedList->getNext())) {
			if ((val=bg->getValue("pcfs.name"))) FsList[NumFs].name = val;
			if ((val=bg->getValue("pcfs.root_dir"))) FsList[NumFs].root_dir = val;
			if ((val=bg->getValue("pcfs.mount_dir"))) FsList[NumFs].mount_dir = val;
			if ((val=bg->getValue("pcfs.auto_mount"))) FsList[NumFs].auto_mount = val;
			if ((val=bg->getValue("pcfs.device"))) FsList[NumFs].device = val;
			if ((val=bg->getValue("pcfs.param_path"))) FsList[NumFs].param_path = val;
#if 0
			printf("id:%u\nname:%s\nroot_dir:%s\nmount_dir:%s\ndevice:%s\nparam_path:%s\n\n", 
				NumFs,
				FsList[NumFs].name, 
				FsList[NumFs].root_dir, 
				FsList[NumFs].mount_dir, 
				FsList[NumFs].device,
				FsList[NumFs].param_path);
#endif
			NumFs++;
		}
		return NumFs;
	}

	dgt_sint32 mount(dgt_uint16 pcfs_id,dgt_uint16 type) throw(DgcExcept)
	{
		if (pcfs_id < NumFs) {
			dgt_schar	pcfs_id_str[32]={0,};
			dgt_schar	proc_path[257]={0,};
			dgt_schar*	args[10]={0,};
			if (type == MTT_MOUNT) {
				sprintf(pcfs_id_str,"%u",pcfs_id);
		                sprintf(proc_path,"%s/bin/%s",getenv("SOHA_HOME"),PCFS_DAEMON_BIN);
				args[0] = (dgt_schar*)PCFS_DAEMON_BIN;
				args[1] = (dgt_schar*)"-r";
				args[2] = FsList[pcfs_id].root_dir;
				args[3] = (dgt_schar*)"-p";
				args[4] = FsList[pcfs_id].param_path;
				args[5] = (dgt_schar*)"-i";
				args[6] = pcfs_id_str;
				args[7] = FsList[pcfs_id].mount_dir;
				args[8] = (dgt_schar*)0;
			} else {
				sprintf(proc_path,"%s/%s",PCFS_UMOUNT_DIR,PCFS_UMOUNT_BIN);
				args[0] = (dgt_schar*)PCFS_UMOUNT_BIN;
				args[1] = (dgt_schar*)"-u";
				args[2] = FsList[pcfs_id].mount_dir;
				args[3] = (dgt_schar*)0;
			}
			pid_t	pid = 0;
			if ((pid=fork()) < 0) {
				THROWnR(DgcOsExcept(errno,new DgcError(SPOS,"fork for [%s] failed",proc_path)),-1);
			} else if (pid == 0) {
				if (fork()) exit(0);
				setsid();
				execv(proc_path, args);
				exit(errno);
			}
			dgt_sint32 status;
			waitpid(pid,&status,0);
			return 0;
		}
		THROWnR(DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,new DgcError(SPOS,"invalid pcfs id[%u]",pcfs_id)),-1);
	}
};

#endif
