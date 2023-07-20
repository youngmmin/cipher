/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccAgentStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2017. 6. 30
 *   Description        :       agent statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_AGENT_STMT_H
#define PCC_AGENT_STMT_H

#include "DgcMemRows.h"
#include "DgcDbNet.h"
#include "PccAgentCryptJobPool.h"

#include "DgcFileStream.h"

class PccAgentStmt : public DgcObject {
  private:
  protected:
	PccAgentCryptJobPool&	JobPool;
	DgcMemRows*		UserVarRows;    // user variable rows
	DgcClass*		SelectListDef;  // row definition for select list
	dgt_sint8		IsExecuted;	// execution flag
  public:
	static const dgt_sint16 NOT_FOUND = -209;

	PccAgentStmt(PccAgentCryptJobPool& job_pool);
	virtual ~PccAgentStmt();
	virtual dgt_sint32 defineUserVars(DgcMemRows* mrows) throw(DgcExcept);
	virtual dgt_sint32 execute(DgcMemRows* mrows=0, dgt_sint8 delete_flag=1) throw(DgcExcept);
	virtual DgcClass* fetchListDef() throw(DgcExcept);
	virtual dgt_uint8* fetch() throw(DgcExcept);
};

class PccGetAgentInfoStmt : public PccAgentStmt {
  private:
	pcct_get_agent_info	AgentInfo;
	dgt_sint32	CurrIdx;
  protected:
  public:
	PccGetAgentInfoStmt(PccAgentCryptJobPool& job_pool, dgt_sint32 sess_id);
	virtual ~PccGetAgentInfoStmt();

	virtual dgt_sint32	execute(DgcMemRows* mrows=0, dgt_sint8 delete_flag=1) throw(DgcExcept);
	virtual dgt_uint8*	fetch() throw(DgcExcept);
};

class PccSetParamsStmt : public PccAgentStmt {
  private:
	pcct_crypt_stat		CryptStat;
	PccAgentCryptJob*	CurrJob;
	dgt_uint32		ParamTextLen;
	dgt_schar*		ParamText;
  protected:
  public:
	PccSetParamsStmt(PccAgentCryptJobPool& job_pool);
	virtual ~PccSetParamsStmt();

	virtual dgt_sint32	execute(DgcMemRows* mrows=0, dgt_sint8 delete_flag=1) throw(DgcExcept);
	virtual dgt_uint8*	fetch() throw(DgcExcept);
};

class PccGetDirEntryStmt : public PccAgentStmt {
  private:
	dgt_schar	DirPath[1025];
	dgt_schar	SrcFile[1257];
	DIR*		DirPtr;
	pcct_dir_entry	DirEntry;
	PccAgentCryptJob* CryptJob;
	PccCryptDir*	CryptDir;
	dgt_sint32	NumEntry;
	dgt_sint32	TotalCount;
	dgt_sint32	FetchCount;
	dgt_sint64	LastFetchOffset;
	dgt_sint8	IsDirectory;
  protected:
  public:
	PccGetDirEntryStmt(PccAgentCryptJobPool& job_pool);
	virtual ~PccGetDirEntryStmt();

	virtual dgt_sint32	execute(DgcMemRows* mrows=0, dgt_sint8 delete_flag=1) throw(DgcExcept);
	virtual dgt_uint8*	fetch() throw(DgcExcept);
};

class PccGetCryptStatStmt : public PccAgentStmt {
  private:
	static const dgt_sint32 MAX_DIRS = 5000;
	DgcMemRows*	CryptStat;
  protected:
  public:
	PccGetCryptStatStmt(PccAgentCryptJobPool& job_pool);
	virtual ~PccGetCryptStatStmt();

	virtual dgt_sint32	execute(DgcMemRows* mrows=0, dgt_sint8 delete_flag=1) throw(DgcExcept);
	virtual dgt_uint8*	fetch() throw(DgcExcept);
};

class PccGetDirCryptStatStmt : public PccAgentStmt {
  private:
	pcct_crypt_stat	CryptStat;
	dgt_uint8	FetchFlag;
  protected:
  public:
	PccGetDirCryptStatStmt(PccAgentCryptJobPool& job_pool);
	virtual ~PccGetDirCryptStatStmt();

	virtual dgt_sint32	execute(DgcMemRows* mrows=0, dgt_sint8 delete_flag=1) throw(DgcExcept);
	virtual dgt_uint8*	fetch() throw(DgcExcept);
};

class PccDropJobStmt : public PccAgentStmt {
  private:
  protected:
  public:
	PccDropJobStmt(PccAgentCryptJobPool& job_pool);
	virtual ~PccDropJobStmt();

	virtual dgt_sint32	execute(DgcMemRows* mrows=0, dgt_sint8 delete_flag=1) throw(DgcExcept);
	virtual dgt_uint8*	fetch() throw(DgcExcept);
};

class PccCryptFileStmt : public PccAgentStmt {
  private:
	  typedef struct {
		  dgt_schar	in_file_name[2049];
		  dgt_schar	out_file_name[2049];
	  } pcct_target_list;
	dgt_sint32	SessionId;
	dgt_sint32	CryptParamLen;
	dgt_schar*	CryptParam;
	pcct_crypt_file_in* CryptFileIn; 
	pcct_crypt_file_out* CryptFileOut;
	DgcMemRows*	TargetList;
	dgt_schar OutExtension[16];
  protected:
  public:
	PccCryptFileStmt(PccAgentCryptJobPool& job_pool);
	virtual ~PccCryptFileStmt();

	virtual dgt_sint32	execute(DgcMemRows* mrows=0, dgt_sint8 delete_flag=1) throw(DgcExcept);
	virtual dgt_uint8*	fetch() throw(DgcExcept);
			dgt_sint32  filter(const dgt_schar* src_dir, const dgt_schar* dst_dir) throw(DgcExcept);
			dgt_sint32 buildParam() throw(DgcExcept);
};

class PccRemoveFileStmt : public PccAgentStmt {
  private:
	pcct_crypt_file_out* CryptFileOut;
  protected:
  public:
	PccRemoveFileStmt(PccAgentCryptJobPool& job_pool);
	virtual ~PccRemoveFileStmt();

	virtual dgt_sint32	execute(DgcMemRows* mrows=0, dgt_sint8 delete_flag=1) throw(DgcExcept);
	virtual dgt_uint8*	fetch() throw(DgcExcept);
};

class PccGetTargetListStmt : public PccAgentStmt {
  private:
	DgcMemRows*	TargetList;
  protected:
  public:
	PccGetTargetListStmt(PccAgentCryptJobPool& job_pool);
	virtual ~PccGetTargetListStmt();

	virtual dgt_sint32	execute(DgcMemRows* mrows=0, dgt_sint8 delete_flag=1) throw(DgcExcept);
	virtual dgt_uint8*	fetch() throw(DgcExcept);
};

class PccRecollectCryptDirStmt : public PccAgentStmt {
  private:
	  dgt_uint8	FetchFlag;
	  pcct_recollect_crypt_dir_out RecollectCryptDirOut;
  protected:
  public:
	PccRecollectCryptDirStmt(PccAgentCryptJobPool& job_pool);
	virtual ~PccRecollectCryptDirStmt();

	virtual dgt_sint32	execute(DgcMemRows* mrows=0, dgt_sint8 delete_flag=1) throw(DgcExcept);
	virtual dgt_uint8*	fetch() throw(DgcExcept);
};

class PccValidationFileStmt : public PccAgentStmt {
  private:
	pcct_crypt_file_out* CryptFileOut;
  protected:
  public:
	PccValidationFileStmt(PccAgentCryptJobPool& job_pool);
	virtual ~PccValidationFileStmt();

	virtual dgt_sint32	execute(DgcMemRows* mrows=0, dgt_sint8 delete_flag=1) throw(DgcExcept);
	virtual dgt_uint8*	fetch() throw(DgcExcept);
};

#endif
