/*******************************************************************
 *   File Type          :       File Cipher Agent classes declaration
 *   Classes            :       PccCryptDir
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 18
 *   Description        :
 *   Modification history
 *   date                    modification
 *   180713					 add isTargetFile, isTargetDir, compileDirPttns,
compileFilePttns member
 *   						 remove statdir
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_CRYPT_DIR_H
#define PCC_CRYPT_DIR_H

#include <regex.h>

#include "../../../../lib/cipher/PccRegExprList.h"
#include "PcaApiSessionPool.h"
#include "PccCryptSchedule.h"
#include "PccCryptTargetFileQueue.h"
#include "PccCryptZone.h"

typedef struct {
    dgt_sint32 dir_depth;
    dgt_sint32 src_file_blen;
    dgt_sint32 dst_file_blen;
    dgt_schar* src_file;
    dgt_schar* dst_file;
} pct_crypt_dir_file;

typedef struct {
    dgt_sint32 version;
    dgt_sint32 search_first_depth;
    dgt_sint32 search_last_depth;
    dgt_sint32 enc_first_depth;
    dgt_sint32 enc_last_depth;
} pct_crypt_zone_dir_rule;

class PccCryptDir : public DgcObject {
   private:
    static const dgt_sint32 MAX_FILE_LEN = 1256;
    static const dgt_sint32 MAX_DIR_DEPTH = 100;
    dgt_sint64 DirID;  // crypt directory id
    PccCryptSchedule& Schedule;
    PccCryptTargetFileQueue& FileQueue;
    PccCryptTargetFileQueue& MigrationFileQueue;
    PccCryptZone* CryptZone;
    dgt_sint32 CurrDirDepth;
    pct_crypt_dir_file DirFileList[MAX_DIR_DEPTH];
    dgt_schar* SrcDir;
    dgt_schar* DstDir;
    dgt_schar* ErrDir;
    dgt_schar* TmpSrcPath;
    dgt_schar* TmpDstPath;
    PccCryptMir* CryptMir;
    pcct_crypt_stat CryptStat;
    pcct_crypt_stat TmpCryptStat;
    dgt_uint8 Status;
    dgt_slock DirLock;
    pct_crypt_zone_dir_rule DirRule;
    PccRegExprList* DirExprs;   // target directory filter
    PccRegExprList* FileExprs;  // target file directory filter
    dgt_sint32 TraceLevel;
    dgt_sint8 cryptStatus(const dgt_schar* file_path) throw(DgcExcept);

    dgt_void filter0(
        PccCryptMir* parent_mir, dgt_schar* src_dir, dgt_schar* dst_dir,
        dgt_sint32 is_target_dir =
            1) throw(DgcExcept);  // Full directory depth filter (crypt)
    dgt_void filter1(
        PccCryptMir* parent_mir, const dgt_schar* src_dir,
        const dgt_schar* dst_dir,
        dgt_uint8 is_target_dir =
            0) throw(DgcExcept);  // Scoped directory depth filter (crypt)
    dgt_void filter2(PccCryptMir* parent_mir, dgt_schar* src_dir,
                     dgt_sint32 is_target_dir =
                         1) throw(DgcExcept);  // Full directory depth filter
                                               // (pattern detect)
    dgt_sint64 loadDetectRqst(PccCryptMir* parent_mir);

   protected:
   public:
    PccCryptDir(dgt_sint64 dir_id, PccCryptSchedule& schedule,
                PccCryptTargetFileQueue& file_queue,
                PccCryptTargetFileQueue& migration_file_queue,
                PccCryptZone* crypt_zone, const dgt_schar* src_dir,
                const dgt_schar* dst_dir = 0,
                pct_crypt_zone_dir_rule* dir_rule = 0,
                dgt_sint32 trace_level = 0, dgt_uint8 status = 1);
    virtual ~PccCryptDir();

    inline dgt_sint8 lock() { return DgcSpinLock::lock(&DirLock); };
    inline dgt_void unlock() { DgcSpinLock::unlock(&DirLock); };
    inline dgt_void setSrcDir(const dgt_schar* src_dir) {
        memset(SrcDir, 0, MAX_FILE_LEN + 1);
        strncpy(SrcDir, src_dir, dg_strlen(src_dir));
    };
    inline dgt_void setDstDir(const dgt_schar* dst_dir) {
        memset(DstDir, 0, MAX_FILE_LEN + 1);
        strncpy(DstDir, dst_dir, dg_strlen(dst_dir));
    };
    inline dgt_void setTmpSrcPath(const dgt_schar* src_dir) {
        memset(TmpSrcPath, 0, 4500);
        strncpy(TmpSrcPath, src_dir, dg_strlen(src_dir));
    };
    inline dgt_void setTmpDstPath(const dgt_schar* dst_dir) {
        memset(TmpDstPath, 0, 4500);
        strncpy(TmpDstPath, dst_dir, dg_strlen(dst_dir));
    };
    inline dgt_void setStatus(dgt_uint8 status) {
        Status = status;
        CryptStat.job_status = status;
    };
    inline dgt_void setDirRule(pct_crypt_zone_dir_rule* dir_rule) {
        if (dir_rule)
            memcpy(&DirRule, dir_rule, sizeof(pct_crypt_zone_dir_rule));
    };

    inline dgt_sint32 dirRuleVersion() { return DirRule.version; };
    inline pct_crypt_zone_dir_rule* dirRule() { return &DirRule; };
    inline dgt_uint8 isSearchDirDepth(dgt_sint32 curr_depth) {
        if (curr_depth >= DirRule.search_first_depth &&
            curr_depth <= DirRule.search_last_depth)
            return 1;
        return 0;
    };
    inline dgt_uint8 isEncDirDepth(dgt_sint32 curr_depth) {
        if (curr_depth >= DirRule.enc_first_depth &&
            curr_depth <= DirRule.enc_last_depth)
            return 1;
        return 0;
    };

    inline PccCryptMir* cryptMir() { return CryptMir; };
    inline pcct_crypt_stat* cryptStat() { return &CryptStat; };
    inline dgt_sint64 dirID() { return DirID; };
    inline PccCryptZone* cryptZone() { return CryptZone; };
    inline const dgt_schar* srcDir() { return SrcDir; };
    inline const dgt_schar* dstDir() { return DstDir; };
    inline dgt_uint8 status() { return Status; };
    dgt_sint32 filter() throw(DgcExcept);
    dgt_sint32 countCryptFile(dgt_schar* src_dir,
                              dgt_sint8 encrypt_flag = 1) throw(DgcExcept);
    dgt_sint32 compileDirPttns(DgcBgrammer* bg,
                               dgt_schar* err_string) throw(DgcExcept);
    dgt_sint32 compileFilePttns(DgcBgrammer* bg,
                                dgt_schar* err_string) throw(DgcExcept);
    dgt_sint32 isTargetDir(const dgt_schar* src_dir);
    dgt_sint32 isTargetFile(const dgt_schar* src_file);
};

#endif
