/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccPcfsGetListStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2018. 7. 17
 *   Description        :       get PCFS list
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccAgentStmt.h"
#include "PccPcfsStat.h"

PccPcfsGetListStmt::PccPcfsGetListStmt(PccAgentCryptJobPool& job_pool)
	: PccAgentStmt(job_pool),CurrFs(0)
{
	SelectListDef = new DgcClass("select_list", 7);
	SelectListDef->addAttr(DGC_UB2, 0, "pcfs_id");
	SelectListDef->addAttr(DGC_SCHR, 33, "name");
	SelectListDef->addAttr(DGC_SCHR, 257, "root_dir");
	SelectListDef->addAttr(DGC_SCHR, 257, "mount_dir");
	SelectListDef->addAttr(DGC_SCHR, 33, "device");
	SelectListDef->addAttr(DGC_SCHR, 11, "auto_mount");
	SelectListDef->addAttr(DGC_SCHR, 11, "status");
}
	
PccPcfsGetListStmt::~PccPcfsGetListStmt()
{
}

dgt_sint32 PccPcfsGetListStmt::execute(DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcExcept)
{
	if (FsConfig.parse() < 0) {
		ATHROWnR(DgcError(SPOS,"parse failed"),-1);
	}
	IsExecuted = 1;
	CurrFs = 0;
	return 0;
}

dgt_uint8* PccPcfsGetListStmt::fetch() throw(DgcExcept)
{
	if (IsExecuted == 0) {
		THROWnR(DgcDbNetExcept(DGC_EC_DN_INVALID_ST,new DgcError(SPOS,"can't fetch without execution")),0);
        }
	if (CurrFs == FsConfig.numFs()) {
		THROWnR(DgcDbNetExcept(NOT_FOUND,new DgcError(SPOS,"not found")),0);
	}
	pcfst_fs_attr_list* curr_fs_attr = FsConfig.fsAttrsByIdx(CurrFs);
	memset(&FsGetList,0,sizeof(FsGetList));
	FsGetList.pcfs_id = CurrFs++;
	strncpy(FsGetList.name,curr_fs_attr->name,32);
	strncpy(FsGetList.root_dir,curr_fs_attr->root_dir,256);
	strncpy(FsGetList.mount_dir,curr_fs_attr->mount_dir,256);
	strncpy(FsGetList.device,curr_fs_attr->device,32);
	strncpy(FsGetList.auto_mount,curr_fs_attr->auto_mount,10);
	PccPcfsStat	pcfs_stat(FsGetList.pcfs_id);
	pcfs_stat.getStat();
#ifndef WIN32
	if (pcfs_stat.statPtr()->pid == 0 || kill((pid_t)pcfs_stat.statPtr()->pid,0)) strncpy(FsGetList.status,"unmount",7);
#else
	if (pcfs_stat.statPtr()->pid == 0/* || kill((pid_t)pcfs_stat.statPtr()->pid,0)*/) strncpy(FsGetList.status,"unmount",7);
#endif
	else strncpy(FsGetList.status,"mount",5);
	return (dgt_uint8*)&FsGetList;
}
