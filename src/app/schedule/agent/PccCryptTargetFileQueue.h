/*******************************************************************
 *   File Type          :       File Cipher Agent classes declaration
 *   Classes            :       PccCryptTargetFile
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 18
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_CRYPT_TARGET_FILE_QUEUE_H
#define PCC_CRYPT_TARGET_FILE_QUEUE_H

#include "DgcMemRows.h"
#include "PccAgentMsg.h"
#include "PccCryptMir.h"

class PccCryptTargetFile : public DgcObject {
   private:
    dgt_sint64 DirID;            // crypt directory id
    dgt_sint64 ZoneID;           // crypt zone id
    PccCryptMir* CryptMir;       // crypt mirror directory pointer
    pcct_file_node* FileNode;    // file node pointer
    pcct_crypt_stat* CryptStat;  // crypt statistics
    dgt_schar* SrcFileName;      // source file name
    dgt_schar* DstFileName;      // output file name
    dgt_sint32 SrcFileNameLen;
    dgt_sint32 DstFileNameLen;
    dgt_sint32 SrcFileNamePos;  // source file name position
    dgt_sint32 DstFileNamePos;  // ouput file name position
    dgt_sint32
        SameFileFlag;  // indicator if source and ouput file names are the same
    dgt_uint8 BackupFlag;        // sorcue file bakcup flag
    dgt_uint8 OutExtensionFlag;  // out extension flag
    dgt_sint32
        ErrCode;        // indicator if source and ouput file names are the same
    dgt_schar* ErrMsg;  // indicator if source and ouput file names are the same
    dgt_time InputTime;
    PccCryptTargetFile* Next;  // next target file pointer in a list

   protected:
   public:
    static const dgt_sint32 INIT_FILE_NAME_LEN = 2048;
    static const dgt_sint32 EXTRA_FILE_NAME_LEN = 256;
    static const dgt_sint32 MAX_ERROR_MSG = 1024;
    PccCryptTargetFile();
    virtual ~PccCryptTargetFile();
    inline dgt_void setBackupFlag(dgt_uint8 bkup_flag) {
        BackupFlag = bkup_flag;
    };
    inline dgt_void setOutExtensionFlag(dgt_uint8 out_extension_flag) {
        OutExtensionFlag = out_extension_flag;
    };
    inline dgt_void setNext(PccCryptTargetFile* next = 0) { Next = next; };
    inline dgt_uint8 backupFlag() { return BackupFlag; };
    inline dgt_uint8 outExtensionFlag() { return OutExtensionFlag; };
    inline dgt_sint64 dirID() { return DirID; };
    inline dgt_sint64 zoneID() { return ZoneID; };
    inline PccCryptMir* cryptMir() { return CryptMir; };
    inline pcct_file_node* fileNode() { return FileNode; };
    inline pcct_crypt_stat* cryptStat() { return CryptStat; };
    inline const dgt_schar* srcFileName() { return SrcFileName; };
    inline const dgt_schar* dstFileName() { return DstFileName; };
    inline dgt_sint32 srcFileNameLen() { return SrcFileNameLen; };
    inline dgt_sint32 dstFileNameLen() { return DstFileNameLen; };
    inline dgt_sint32 srcFileNamePos() { return SrcFileNamePos; };
    inline dgt_sint32 dstFileNamePos() { return DstFileNamePos; };
    inline dgt_sint32 errCode() { return ErrCode; };
    inline const dgt_schar* errMsg() { return ErrMsg; };
    inline dgt_time inputTime() { return InputTime; };

    inline dgt_sint32 isSameFile() { return SameFileFlag; };
    // added by shson 2018.04.06 for FailFile managing
    inline dgt_void setErrCode(dgt_sint32 error_code) { ErrCode = error_code; };
    inline dgt_void setErrMsg(const dgt_schar* error_msg) {
        if (error_msg && strlen(error_msg) != 0) {
            if (ErrMsg == 0) ErrMsg = new dgt_schar[MAX_ERROR_MSG];
            memset(ErrMsg, 0, MAX_ERROR_MSG);
            strncpy(ErrMsg, error_msg, MAX_ERROR_MSG);
        }
    };
    inline PccCryptTargetFile* next() { return Next; };
    dgt_void reset(dgt_sint64 dir_id, dgt_sint64 zone_id,
                   PccCryptMir* crypt_mir, pcct_file_node* file_node,
                   pcct_crypt_stat* cs, const dgt_schar* src_file_name,
                   dgt_sint32 src_file_name_pos,
                   const dgt_schar* dst_file_name = 0,
                   dgt_sint32 dst_file_name_pos = 0, dgt_sint32 error_code = 0,
                   const dgt_schar* error_msg = 0);

    dgt_void copy(PccCryptTargetFile* tf);
};

#if 0
class PccCryptFailFile : public PccCryptTargetFile {
  private:
	dgt_sint32		ErrCode;
	dgt_schar*		ErrMsg; // source file name
  protected:
  public:
	static const dgt_sint32 MAX_ERROR_MSG	= 1024;
	PccCryptFailFile(); 
	virtual ~PccCryptFailFile();
	inline dgt_void setErrCode(dgt_sint32 error_code) { ErrCode = error_code; };
	inline dgt_void setErrMsg(dgt_schar* error_msg) { 
		if (error_msg && strlen(error_msg) != 0) {
			memset(ErrMsg, 0, MAX_ERROR_MSG); 
			strncpy(ErrMsg, error_msg, MAX_ERROR_MSG); 
		}
	};
};
#endif

class PccCryptTargetFileQueue : public DgcObject {
   private:
    static const dgt_sint32 MAX_TARGET_FILE = 1000;
    PccCryptTargetFile* TargetFiles;  // target file pool
    PccCryptTargetFile* First;        // queue header
    PccCryptTargetFile* Last;         // queue last
    PccCryptTargetFile* FirstFree;    // free list header
    PccCryptTargetFile* LastFree;     // free list last
    dgt_sint32 NumFiles;              // the size of target file pool
    dgt_sint32 FileCount;
    PccCryptTargetFile NoHeapQueue;
    dgt_slock ListLock;  // concurrency control spin lock
   protected:
   public:
    PccCryptTargetFileQueue(dgt_sint32 num_files = MAX_TARGET_FILE);
    virtual ~PccCryptTargetFileQueue();
    inline dgt_sint32 queueSize() { return NumFiles; }
    inline dgt_sint32 fileCount() { return FileCount; }
    inline dgt_sint32 isFull() {
        if (NumFiles <= FileCount)
            return 1;
        else
            return 0;
    }

    dgt_sint32 initializeQueue(dgt_sint32 num_files);
    dgt_sint32 get(PccCryptTargetFile* tf);
    dgt_sint32 queueCopy(DgcMemRows* tf);
    dgt_sint32 put(dgt_sint64 dir_id, dgt_sint64 zone_id,
                   PccCryptMir* crypt_mir, pcct_file_node* file_node,
                   pcct_crypt_stat* cs, const dgt_schar* src_file_name,
                   dgt_sint32 src_file_name_pos,
                   const dgt_schar* dst_file_name = 0,
                   dgt_sint32 dst_file_name_pos = 0, dgt_sint32 error_code = 0,
                   const dgt_schar* error_msg = 0);
    dgt_void dump();
};

#endif
