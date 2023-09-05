/*******************************************************************
 *   File Type          :       File Cipher Agent classes definition
 *   Classes            :       PccCryptDir
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 30
 *   Description        :
 *   Modification history
 *   date                    modification
 *   180713					 add isTargetFile, isTargetDir, compileDirPttns,
compileFilePttns member
 *   						 remove statdir
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccCryptDir.h"

#include "DgcWorker.h"
#include "PcaApiSessionPool.h"
#include "PccFileCryptor.h"

PccCryptDir::PccCryptDir(dgt_sint64 dir_id, PccCryptSchedule& schedule,
                         PccCryptTargetFileQueue& file_queue,
                         PccCryptTargetFileQueue& migration_file_queue,
                         PccCryptZone* crypt_zone, const dgt_schar* src_dir,
                         const dgt_schar* dst_dir,
                         pct_crypt_zone_dir_rule* dir_rule,
                         dgt_sint32 trace_level, dgt_uint8 status)
    : DirID(dir_id),
      Schedule(schedule),
      FileQueue(file_queue),
      MigrationFileQueue(migration_file_queue),
      CryptZone(crypt_zone),
      CryptMir(0) {
    CurrDirDepth = 0;
    for (dgt_sint32 i = 0; i < MAX_DIR_DEPTH; i++) {
        memset(&DirFileList[i], 0, sizeof(pct_crypt_dir_file));
    }
    SrcDir = DstDir = ErrDir = 0;
    SrcDir = new dgt_schar[MAX_FILE_LEN + 1];
    DstDir = new dgt_schar[MAX_FILE_LEN + 1];
    ErrDir = new dgt_schar[MAX_FILE_LEN + 1];
    memset(SrcDir, 0, MAX_FILE_LEN + 1);
    memset(DstDir, 0, MAX_FILE_LEN + 1);
    memset(ErrDir, 0, MAX_FILE_LEN + 1);

    strncpy(SrcDir, src_dir, dg_strlen(src_dir));
    if (dst_dir) strncpy(DstDir, dst_dir, dg_strlen(dst_dir));
    memset(&DirRule, 0, sizeof(pct_crypt_zone_dir_rule));
    if (dir_rule) memcpy(&DirRule, dir_rule, sizeof(pct_crypt_zone_dir_rule));

    TmpSrcPath = TmpDstPath = 0;
    TmpSrcPath = new dgt_schar[4500];
    TmpDstPath = new dgt_schar[4500];
    memset(TmpSrcPath, 0, 4500);
    memset(TmpDstPath, 0, 4500);

    memset(&CryptStat, 0, sizeof(pcct_crypt_stat));
    memset(&TmpCryptStat, 0, sizeof(pcct_crypt_stat));
    Status = PCC_STATUS_TYPE_RUN;
    DirExprs = 0;
    FileExprs = 0;
    TraceLevel = trace_level;
    Status = status;
    unlock();
}

PccCryptDir::~PccCryptDir() {
    if (DirExprs) delete DirExprs;
    if (FileExprs) delete FileExprs;
    if (CryptMir) delete CryptMir;
    if (SrcDir) delete SrcDir;
    if (DstDir) delete DstDir;
    if (ErrDir) delete ErrDir;
    if (TmpSrcPath) delete TmpSrcPath;
    if (TmpDstPath) delete TmpDstPath;
    for (dgt_sint32 i = 0; i < MAX_DIR_DEPTH; i++) {
        if (DirFileList[i].src_file) delete DirFileList[i].src_file;
        if (DirFileList[i].dst_file) delete DirFileList[i].dst_file;
    }
}

#if defined(sunos5) || defined(sunos5_x86)

struct ll_dirent {
    struct dirent entry;
    char name_buf[256];
};

#endif

dgt_sint8 PccCryptDir::cryptStatus(const dgt_schar* file_path) throw(
    DgcExcept) {
    dgt_sint8 rtn = 0;
    if (CryptZone->headerFlag()) {
        dgt_header_info header_info;
        memset(&header_info, 0, sizeof(dgt_header_info));
        if ((rtn = (dgt_sint8)PccHeaderManager::isEncrypted(
                 file_path, &header_info)) < 0) {
            if (rtn == -3)
                ATHROWnR(
                    DgcError(SPOS, "encrypting is currently underway"),
                    -3);  // this case is currently underway ,file encryptiong
            else if (rtn == -1)
                ATHROWnR(DgcError(SPOS, "header checking crypt status failed"),
                         -1);
        }
#if 1
        // added by shson 2019.03.13
        // for auto background migration
        // compare current key_id  and key_id of enc_file
        // if not same key_id, return 3
        // 3 mean migration target
        dgt_sint64 curr_key_id = CryptZone->keyId();
        if (rtn == 1 && curr_key_id != 10 &&
            curr_key_id < 255) {  // chageable key
            dgt_uint8 enc_file_key_id = 0;
            // get file key id
            if ((header_info.version == 2 || header_info.version == 3 ||
                 header_info.version == 4) &&
                header_info.key_id) {  // exist key_id in header
                enc_file_key_id = header_info.key_id;
            } else {  // not exist key_id in header, key_id is lastbyte of
                      // encrypted file
                DgcFileStream enc_file(file_path);
                enc_file.seek(-1, SEEK_END);
                enc_file.recvData((dgt_uint8*)&enc_file_key_id, 1);
            }
            // compare current key_id and file key_id
            if ((dgt_uint8)curr_key_id != enc_file_key_id) {
                rtn = 3;
            }
        }  // if (rtn == 1 && check_migration) end
#endif
    } else {  // if (CryptZone->headerFlag()) else
        // no checking crypt_status without the header
        // rtn should be different from crypt_flag even it occur duplicating
        // cryption
        if (CryptZone->encryptFlag())
            rtn = 0;
        else
            rtn = 1;
    }
    return rtn;
}

dgt_sint32 PccCryptDir::countCryptFile(
    dgt_schar* src_dir, dgt_sint8 encrypt_flag) throw(DgcExcept) {
    dgt_sint32 crypt_count = 0;
    DIR* dir_ptr = opendir(src_dir);
    if (dir_ptr == NULL) {
        DgcWorker::PLOG.tprintf(0, "countCryptFile opendir[%s] failed[%s]:\n",
                                src_dir, strerror(errno));
        return -1;
    }
#if defined(sunos5) || defined(sunos5_x86)
    struct ll_dirent ll_entry;
#else
    struct dirent ll_entry;
#endif
    struct dirent* entry = (struct dirent*)&ll_entry;
    struct dirent* result;
    dgt_sint32 rtn = 0;
    dgt_sint32 src_dir_len = dg_strlen(src_dir);
    dgt_schar* src_file = src_dir;

    for (; (rtn = readdir_r(dir_ptr, entry, &result)) == 0;) {  // success
        if (result == NULL) break;                              // end of entry
        sprintf(src_file + src_dir_len, "/%s", entry->d_name);
        struct stat fstat;
        if (stat(src_file, &fstat) < 0) {
            DgcWorker::PLOG.tprintf(0, "stat[%s] failed[%s]:\n", src_file,
                                    strerror(errno));
            continue;
        }

        if (S_ISDIR(fstat.st_mode)) {  // directory
            if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
                crypt_count += countCryptFile(src_file, encrypt_flag);
        } else if (S_ISREG(fstat.st_mode)) {  // file
            dgt_sint8 enc_check = cryptStatus(src_file);
            if (enc_check < 0) {
                DgcExcept* e = EXCEPTnC;
                if (e) {
                    DgcWorker::PLOG.tprintf(0, *e, "isEncrypted[%s] failed:\n",
                                            src_file);
                    delete e;
                }
                continue;
            } else if (enc_check == encrypt_flag)
                crypt_count++;
        }  // else if (S_ISREG(fstat.st_mode)) end
    }      // for end
    closedir(dir_ptr);

    return crypt_count;
}

dgt_void PccCryptDir::filter0(PccCryptMir* parent_mir, dgt_schar* src_dir,
                              dgt_schar* dst_dir,
                              dgt_sint32 is_target_dir) throw(DgcExcept) {
    TmpCryptStat.check_dirs++;
    DIR* dir_ptr = opendir(src_dir);
    if (dir_ptr == NULL) {
        if (errno != ENOENT) {
            DgcWorker::PLOG.tprintf(0, "fileter0 opendir[%s] failed[%s]:\n",
                                    src_dir, strerror(errno));
            TmpCryptStat.check_errors++;
        } else {
            parent_mir->setDropFlag();
        }
        return;
    }
    // parent_mir->openMir(); // removed by jhpark 2017.11.21
#if defined(sunos5) || defined(sunos5_x86)
    struct ll_dirent ll_entry;
#else
    struct dirent ll_entry;
#endif
    struct dirent* entry = (struct dirent*)&ll_entry;
    struct dirent* result;
    dgt_sint32 rtn = 0;
    dgt_sint32 src_dir_len = dg_strlen(src_dir);
    dgt_sint32 dst_dir_len = dg_strlen(dst_dir);
    dgt_schar* src_file = src_dir;
    dgt_schar* dst_file = dst_dir;
    for (; (rtn = readdir_r(dir_ptr, entry, &result)) == 0;) {  // success
        if (Status == PCC_STATUS_TYPE_DELETED ||
            Status == PCC_STATUS_TYPE_PAUSE)
            break;
        if (result == NULL) break;  // end of entry
        sprintf(src_file + src_dir_len, "/%s", entry->d_name);
        sprintf(dst_file + dst_dir_len, "/%s", entry->d_name);
        struct stat fstat;
        if (stat(src_file, &fstat) < 0) {
            DgcWorker::PLOG.tprintf(0, "stat[%s] failed[%s]:\n", src_file,
                                    strerror(errno));
            TmpCryptStat.check_errors++;
            continue;
        }

        if (S_ISDIR(fstat.st_mode)) {  // directory
            if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
                TmpCryptStat.target_dirs++;
                dgt_uint64 ino = entry->d_ino;

                PccCryptMir* child_mir =
                    parent_mir;  // modified by jhpark 2017.11.21
                if (strlen(src_dir) == strlen(dst_dir) &&
                    strncmp(src_dir, dst_dir, strlen(src_dir)) == 0) {
                    filter0(child_mir, src_file, src_file,
                            isTargetDir(src_file + strlen(SrcDir)));
                } else {
                    if (mkdir(dst_file, 0777) < 0 && errno != EEXIST) {
                        DgcWorker::PLOG.tprintf(0, "mkdir[%s] failed[%s]:\n",
                                                dst_file, strerror(errno));
                        TmpCryptStat.check_errors++;
                    } else {
                        filter0(child_mir, src_file, dst_file,
                                isTargetDir(src_file + strlen(SrcDir)));
                    }
                }
            }
        } else if (S_ISREG(fstat.st_mode)) {   // file
            if (is_target_dir == 0) continue;  // not target
            if (fstat.st_size == 0) continue;  // null file check

            //
            // need method which returns crypting status, cryptStatus(const
            // dgt_schar* file_path) with return values: 0 -> text, 1 ->
            // encrypted
            //
            pcct_file_node* file_node = 0;
            dgt_sint8 enc_check = cryptStatus(src_file);
            if (enc_check < 0) {
                DgcExcept* e = EXCEPTnC;
                if (e) {
                    if (enc_check == -3) {
                        if (TraceLevel > 10)
                            DgcWorker::PLOG.tprintf(
                                0, "encrypting is current underway[%s]\n",
                                src_file);
                    } else {
                        DgcWorker::PLOG.tprintf(
                            0, *e, "isEncrypted[%s] failed:\n", src_file);
                        TmpCryptStat.check_errors++;
                    }
                    delete e;
                }
                continue;
            } else if (enc_check == CryptZone->encryptFlag()) {
                continue;
            } else if (enc_check ==
                       3) {  // added by shson 20190313 for auto migration
                TmpCryptStat.migration_target++;

                file_node = parent_mir->checkFileNode(&fstat);
                pr_debug(
                    "entry->d_name[%s] fstat.st_ino[%lld] cllt_time[%d] "
                    "CryptZone->headerFlag()[%u] encrypt_flag[%u:%u]\n",
                    entry->d_name, fstat.st_ino, file_node->cllt_time,
                    CryptZone->headerFlag(), file_node->encrypt_flag,
                    CryptZone->encryptFlag());

                if (Status == PCC_STATUS_TYPE_MIGRATION &&
                    file_node->check_migration == 0) {
                    while (MigrationFileQueue.put(
                               DirID, CryptZone->zoneID(), parent_mir,
                               file_node, &CryptStat, src_file, src_dir_len,
                               src_file, src_dir_len) == 0)
                        napAtick();
                    file_node->check_migration = 1;
                    if (TraceLevel > 20)
                        DgcWorker::PLOG.tprintf(
                            0, "input migration file queue src_file[%s]\n",
                            src_file);
                }
                continue;
            }  // else if (enc_check == 3) end

            TmpCryptStat.check_files++;

            if (isTargetFile(entry->d_name)) {
                struct timeval ct;
                gettimeofday(&ct, 0);
                if (file_node == 0)
                    file_node = parent_mir->checkFileNode(&fstat);
                if (!file_node) continue;

                if (file_node->cllt_time) continue;  // already collected

                if (file_node->ref_count == 1) CryptStat.target_files++;

                // for check already crypted file by shson 2018.10.01
                if (CryptZone->backupFlag()) {
                    dgt_sint32 file_len = dg_strlen(dst_file);
                    if (CryptZone->hasOutExtension()) {
                        strcat(dst_file, ".");
                        strcat(dst_file, CryptZone->outExtension());
                    }

                    struct stat check_fstat;
                    if (stat(dst_file, &check_fstat) == 0)

                    {
                        if (TraceLevel > 10)
                            DgcWorker::PLOG.tprintf(0,
                                                    "src_file[%s] is already "
                                                    "crypted, dst_file[%s] \n",
                                                    src_file, dst_file);
                        file_node->cllt_time = file_node->ctst_time =
                            file_node->cted_time = fstat.st_mtime;
                        continue;
                    }
                    dst_file[file_len] = '\0';
                }

                //
                // not collected yet so need to check close time & crypt header
                //
                if ((ct.tv_sec - fstat.st_mtime) > CryptZone->closeAfter()) {
                    while (FileQueue.put(DirID, CryptZone->zoneID(), parent_mir,
                                         file_node, &CryptStat, src_file,
                                         src_dir_len, dst_file,
                                         dst_dir_len) == 0)
                        napAtick();
                    file_node->cllt_time = ct.tv_sec;
                    CryptStat.input_files++;
                    CryptStat.input_bytes += fstat.st_size;

                    if (TraceLevel > 20)
                        DgcWorker::PLOG.tprintf(
                            0, "input file queue src_file[%s] dst_file[%s]\n",
                            src_file, dst_file);

                    CryptStat.check_dirs = TmpCryptStat.check_dirs;
                    CryptStat.check_errors = TmpCryptStat.check_errors;
                    CryptStat.target_dirs = TmpCryptStat.target_dirs;
                    CryptStat.check_files = TmpCryptStat.check_files;
                }  // if ((ct.tv_sec - fstat.st_mtime) >
                   // CryptZone->closeAfter())
            }  // if (isTargetFile(entry->d_name))
        }      // else if (S_ISREG(fstat.st_mode))
    }          // for (;(rtn=readdir_r(dir_ptr,entry,&result)) == 0;) {
    if (rtn) {
        DgcWorker::PLOG.tprintf(0, "readdir_r[%s] failed[%s]:\n", src_dir,
                                strerror(errno));
        TmpCryptStat.check_errors++;
    }
    closedir(dir_ptr);
    if (dg_strlen(SrcDir) == src_dir_len) {
        CryptStat.check_dirs = TmpCryptStat.check_dirs;
        CryptStat.check_errors = TmpCryptStat.check_errors;
        CryptStat.target_dirs = TmpCryptStat.target_dirs;
        CryptStat.check_files = TmpCryptStat.check_files;
        CryptStat.migration_target = TmpCryptStat.migration_target;

        memset(&TmpCryptStat, 0, sizeof(TmpCryptStat));
    }
}
//2023.09.01  Function to find * in pattern
dgt_sint32 PccCryptDir::pttnsFindAster(PccRegExprList* Exprs) {
    
    if(Exprs == 0){
        return 0;
    }
    exp_type* preg;
    Exprs->rewind();
    
    while ((preg = Exprs->nextPttn())) {
        // Check if the pattern contains an asterisk '*'
        if ((strcmp(preg->exp, ".*") == 0) || strcmp(preg->exp, "..*") == 0 || strcmp(preg->exp, "..*.*") == 0) {
            return 1;  // found an asterisk in the pattern
        }
    }

    return 0;  // no asterisk found in any pattern
}
dgt_void PccCryptDir::filter1(PccCryptMir* parent_mir, const dgt_schar* src_dir,
                              const dgt_schar* dst_dir,
                              dgt_uint8 is_target_dir) throw(DgcExcept) {
    CurrDirDepth++;
    if (CurrDirDepth >= MAX_DIR_DEPTH) {
        DgcWorker::PLOG.tprintf(
            0, "[%s] current depth is too much deep to search.\n", src_dir);
        TmpCryptStat.check_errors++;
        CurrDirDepth--;
        return;
    }

    TmpCryptStat.check_dirs++;
    DIR* dir_ptr = opendir(src_dir);
    if (dir_ptr == NULL) {
        if (errno != ENOENT) {
            DgcWorker::PLOG.tprintf(0, "filter1 opendir[%s] failed[%s]:\n",
                                    src_dir, strerror(errno));
            TmpCryptStat.check_errors++;
        } else {
            parent_mir->setDropFlag();
        }
        CurrDirDepth--;
        return;
    }
    // parent_mir->openMir(); // removed by jhpark 2017.11.21
#if defined(sunos5) || defined(sunos5_x86)
    struct ll_dirent ll_entry;
#else
    struct dirent ll_entry;
#endif
    struct dirent* entry = (struct dirent*)&ll_entry;
    struct dirent* result;
    dgt_sint32 rtn = 0;

    for (; (rtn = readdir_r(dir_ptr, entry, &result)) == 0;) {  // success
        if (Status == PCC_STATUS_TYPE_DELETED ||
            Status == PCC_STATUS_TYPE_PAUSE)
            break;
        if (result == NULL) break;  // end of entry

        dgt_sint32 src_file_len =
            dg_strlen(src_dir) + dg_strlen(entry->d_name) + 1;
        if (DirFileList[CurrDirDepth].src_file_blen < src_file_len) {
            if (DirFileList[CurrDirDepth].src_file)
                delete DirFileList[CurrDirDepth].src_file;
            dgt_sint32 buf_len = dg_strlen(src_dir) +
                                 (dg_strlen(entry->d_name) > MAX_FILE_LEN
                                      ? dg_strlen(entry->d_name)
                                      : MAX_FILE_LEN) +
                                 1;
            DirFileList[CurrDirDepth].src_file = new dgt_schar[buf_len];
            DirFileList[CurrDirDepth].src_file_blen = buf_len;
        }
        memset(DirFileList[CurrDirDepth].src_file, 0,
               DirFileList[CurrDirDepth].src_file_blen);
        sprintf(DirFileList[CurrDirDepth].src_file, "%s/%s", src_dir,
                entry->d_name);

        struct stat fstat;
        if (stat(DirFileList[CurrDirDepth].src_file, &fstat) < 0) {
            DgcWorker::PLOG.tprintf(0, "stat[%s] failed[%s]:\n",
                                    DirFileList[CurrDirDepth].src_file,
                                    strerror(errno));
            TmpCryptStat.check_errors++;
            continue;
        }

        dgt_sint32 dst_file_len =
            dg_strlen(dst_dir) + dg_strlen(entry->d_name) + 1;
        if (DirFileList[CurrDirDepth].dst_file_blen < dst_file_len) {
            if (DirFileList[CurrDirDepth].dst_file)
                delete DirFileList[CurrDirDepth].dst_file;
            dgt_sint32 buf_len = dg_strlen(dst_dir) +
                                 (dg_strlen(entry->d_name) > MAX_FILE_LEN
                                      ? dg_strlen(entry->d_name)
                                      : MAX_FILE_LEN) +
                                 1;
            DirFileList[CurrDirDepth].dst_file = new dgt_schar[buf_len];
            DirFileList[CurrDirDepth].dst_file_blen = buf_len;
        }
        memset(DirFileList[CurrDirDepth].dst_file, 0,
               DirFileList[CurrDirDepth].dst_file_blen);
        if (S_ISDIR(fstat.st_mode)) {  // directory
            dgt_uint8 is_target_dir_flag = is_target_dir;
            if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
                if (isSearchDirDepth(CurrDirDepth)) {
                    if (isTargetDir(entry->d_name))
                        is_target_dir_flag = 1;
                    else
                        is_target_dir_flag = 0;
                }
                pr_debug(
                    "directory search : CurrDirDepth[%d] is_target_dir[%u] "
                    "is_target_dir_flag[%d] "
                    "isSearchDirDepth(CurrDirDepth)[%d]\n",
                    CurrDirDepth, is_target_dir, is_target_dir_flag,
                    isSearchDirDepth(CurrDirDepth));
                TmpCryptStat.target_dirs++;
                dgt_uint64 ino = entry->d_ino;

                pr_debug("search dir src_file[%s]\n",
                         DirFileList[CurrDirDepth].src_file);

                // PccCryptMir* child_mir =
                // parent_mir->getChildMir(ino,fstat.st_mtime); // removed by
                // jhpark 2017.11.21 : managing child_mir need a large amount of
                // memory
                PccCryptMir* child_mir =
                    parent_mir;  // modified by jhpark 2017.11.21
                if (src_dir == dst_dir) {
                    filter1(child_mir, DirFileList[CurrDirDepth].src_file,
                            DirFileList[CurrDirDepth].src_file,
                            is_target_dir_flag);
                } else {
                    sprintf(DirFileList[CurrDirDepth].dst_file, "%s/%s",
                            dst_dir, entry->d_name);
                    if (mkdir(DirFileList[CurrDirDepth].dst_file, 0777) < 0 &&
                        errno != EEXIST) {
                        DgcWorker::PLOG.tprintf(
                            0, "mkdir[%s] failed[%s]:\n",
                            DirFileList[CurrDirDepth].dst_file,
                            strerror(errno));
                        TmpCryptStat.check_errors++;
                    } else {
                        filter1(child_mir, DirFileList[CurrDirDepth].src_file,
                                DirFileList[CurrDirDepth].dst_file,
                                is_target_dir_flag);
                    }
                }
            }
        } else if (S_ISREG(fstat.st_mode)) {  // file
            

            //2023.09.01 Process root directory encryption exclusion
            if((CurrDirDepth == 0 && DirExprs != 0) && !pttnsFindAster(DirExprs)){
                continue;
            }
            
            
            //
            // need method which returns crypting status, cryptStatus(const
            // dgt_schar* file_path) with return values: 0 -> text, 1 ->
            // encrypted
            //
            dgt_sint8 enc_check =
                cryptStatus(DirFileList[CurrDirDepth].src_file);
            if (enc_check < 0) {
                DgcExcept* e = EXCEPTnC;
                if (e) {
                    DgcWorker::PLOG.tprintf(0, *e, "isEncrypted[%s] failed:\n",
                                            DirFileList[CurrDirDepth].src_file);
                    delete e;
                }
                TmpCryptStat.check_errors++;
                continue;
            } else if (enc_check == CryptZone->encryptFlag())
                continue;
            TmpCryptStat.check_files++;
            // if (parent_mir->changeFlag() == 0) continue; // removed by jhpark
            // 2017.11.21 : it doesn't work because change_flag is always 1
            pcct_file_node* file_node = 0;
            if (is_target_dir == 0 || isEncDirDepth(CurrDirDepth) == 0)
                continue;
            if (isTargetFile(entry->d_name)) {
                struct timeval ct;
                gettimeofday(&ct, 0);
                file_node = parent_mir->checkFileNode(&fstat);
                pr_debug(
                    "entry->d_name[%s] fstat.st_ino[%lld] cllt_time[%d] "
                    "CryptZone->headerFlag()[%u] encrypt_flag[%u:%u]\n",
                    entry->d_name, fstat.st_ino, file_node->cllt_time,
                    CryptZone->headerFlag(), file_node->encrypt_flag,
                    CryptZone->encryptFlag());

                if (!file_node) continue;
                if (file_node->cllt_time) continue;  // already collected

                if (file_node->ref_count == 1) CryptStat.target_files++;

                //
                // not collected yet so need to check close time & crypt header
                //
                if ((ct.tv_sec - fstat.st_mtime) > CryptZone->closeAfter()) {
                    sprintf(DirFileList[CurrDirDepth].dst_file, "%s/%s",
                            dst_dir, entry->d_name);

                    while (FileQueue.put(DirID, CryptZone->zoneID(), parent_mir,
                                         file_node, &CryptStat,
                                         DirFileList[CurrDirDepth].src_file,
                                         dg_strlen(src_dir),
                                         DirFileList[CurrDirDepth].dst_file,
                                         dg_strlen(dst_dir)) == 0)
                        napAtick();
                    file_node->cllt_time = ct.tv_sec;
                    CryptStat.input_files++;
                    CryptStat.input_bytes += fstat.st_size;
                }
            }
        }
    }

    if (rtn) {
        DgcWorker::PLOG.tprintf(0, "readdir_r[%s] failed[%s]:\n", src_dir,
                                strerror(errno));
        TmpCryptStat.check_errors++;
    }
    closedir(dir_ptr);
    CurrDirDepth--;
    if (SrcDir == src_dir) {
        CryptStat.check_dirs = TmpCryptStat.check_dirs;
        CryptStat.check_errors = TmpCryptStat.check_errors;
        CryptStat.target_dirs = TmpCryptStat.target_dirs;
        CryptStat.check_files = TmpCryptStat.check_files;

        memset(&TmpCryptStat, 0, sizeof(TmpCryptStat));
    }
}

dgt_sint64 PccCryptDir::loadDetectRqst(PccCryptMir* parent_mir) {
    DgcMemRows detect_rqst(4);
    detect_rqst.addAttr(DGC_SB8, 0, "DIR_ID");
    detect_rqst.addAttr(DGC_SB8, 0, "FILE_ID");
    detect_rqst.addAttr(DGC_SB8, 0, "PTTN_NUM");
    detect_rqst.addAttr(DGC_SCHR, 2048, "FILE_NAME");
    detect_rqst.reset();
    detect_rqst.add();
    detect_rqst.next();
    memcpy(detect_rqst.getColPtr(1), &DirID, sizeof(dgt_sint64));

    dgt_sint32 sid = -1;
    if ((sid = PcaApiSessionPool::getApiSession("", "", "", "", "", "", 0)) < 0)
        return 0;

    PcaApiSession* session = 0;
    if ((session = PcaApiSessionPool::getApiSession(sid)) == 0) return 0;

    session->getDetectFileRequest(&detect_rqst);

    struct timeval ct;
    gettimeofday(&ct, 0);

    detect_rqst.rewind();
    while (detect_rqst.next()) {
        pcct_file_node* file_node = 0;
        struct stat tmp;
        memset(&tmp, 0, sizeof(struct stat));
        memcpy(&tmp.st_ino, detect_rqst.getColPtr(2), sizeof(dgt_sint64));
        file_node = parent_mir->checkFileNode(&tmp);
        file_node->encrypt_flag =
            *(dgt_sint64*)detect_rqst.getColPtr(3) ? 2 : 0;
        file_node->cllt_time = file_node->ctst_time = file_node->cted_time =
            ct.tv_sec;
    }
    return detect_rqst.numRows();
}

dgt_void PccCryptDir::filter2(PccCryptMir* parent_mir, dgt_schar* src_dir,
                              dgt_sint32 is_target_dir) throw(DgcExcept) {
    TmpCryptStat.check_dirs++;
    DIR* dir_ptr = opendir(src_dir);
    if (dir_ptr == NULL) {
        if (errno != ENOENT) {
            DgcWorker::PLOG.tprintf(0, "filter2 opendir[%s] failed[%s]:\n",
                                    src_dir, strerror(errno));
            TmpCryptStat.check_errors++;
        } else {
            parent_mir->setDropFlag();
        }
        return;
    }

#if defined(sunos5) || defined(sunos5_x86)
    struct ll_dirent ll_entry;
#else
    struct dirent ll_entry;
#endif
    struct dirent* entry = (struct dirent*)&ll_entry;
    struct dirent* result;
    dgt_sint32 rtn = 0;
    dgt_sint32 src_dir_len = dg_strlen(src_dir);
    dgt_schar* src_file = src_dir;

    for (; (rtn = readdir_r(dir_ptr, entry, &result)) == 0;) {  // success
        if (Status == PCC_STATUS_TYPE_DELETED ||
            Status == PCC_STATUS_TYPE_PAUSE)
            break;
        if (result == NULL) break;  // end of entry
        sprintf(src_file + src_dir_len, "/%s", entry->d_name);
        struct stat fstat;
        if (stat(src_file, &fstat) < 0) {
            DgcWorker::PLOG.tprintf(0, "stat[%s] failed[%s]:\n", src_file,
                                    strerror(errno));
            TmpCryptStat.check_errors++;
            continue;
        }

        if (S_ISDIR(fstat.st_mode)) {  // directory
            if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
                TmpCryptStat.target_dirs++;
                dgt_uint64 ino = entry->d_ino;
                PccCryptMir* child_mir =
                    parent_mir;  // modified by jhpark 2017.11.21
                filter2(child_mir, src_file,
                        isTargetDir(src_file + strlen(SrcDir)));
            }
        } else if (S_ISREG(fstat.st_mode)) {   // file
            if (is_target_dir == 0) continue;  // not target
            pcct_file_node* file_node = 0;
            TmpCryptStat.check_files++;

            if (isTargetFile(entry->d_name)) {
                struct timeval ct;
                gettimeofday(&ct, 0);

                if (file_node == 0)
                    file_node = parent_mir->checkFileNode(&fstat);
                pr_debug(
                    "entry->d_name[%s] fstat.st_ino[%lld] cllt_time[%d] "
                    "detected[%u]\n",
                    entry->d_name, fstat.st_ino, file_node->cllt_time,
                    file_node->encrypt_flag);

                if (!file_node) continue;
                if (file_node->cllt_time) continue;  // already collected

                if (file_node->ref_count == 1) CryptStat.target_files++;

                //
                // not collected yet so need to check close time & crypt header
                //
                if ((ct.tv_sec - fstat.st_mtime) > CryptZone->closeAfter()) {
                    while (FileQueue.put(DirID, CryptZone->zoneID(), parent_mir,
                                         file_node, &CryptStat, src_file,
                                         src_dir_len, 0, 0) == 0)
                        napAtick();
                    file_node->cllt_time = ct.tv_sec;
                    CryptStat.input_files++;
                    CryptStat.input_bytes += fstat.st_size;

                    if (TraceLevel > 20)
                        DgcWorker::PLOG.tprintf(
                            0, "input file queue src_file[%s]\n", src_file);
                    CryptStat.check_dirs = TmpCryptStat.check_dirs;
                    CryptStat.check_errors = TmpCryptStat.check_errors;
                    CryptStat.target_dirs = TmpCryptStat.target_dirs;
                    CryptStat.check_files = TmpCryptStat.check_files;
                }  // if ((ct.tv_sec - fstat.st_mtime) >
                   // CryptZone->closeAfter())
            }  // if (isTargetFile(entry->d_name))
        }      // else if (S_ISREG(fstat.st_mode))
    }          // for (;(rtn=readdir_r(dir_ptr,entry,&result)) == 0;) {
    if (rtn) {
        DgcWorker::PLOG.tprintf(0, "readdir_r[%s] failed[%s]:\n", src_dir,
                                strerror(errno));
        TmpCryptStat.check_errors++;
    }
    closedir(dir_ptr);
    if (SrcDir == src_dir) {
        CryptStat.check_dirs = TmpCryptStat.check_dirs;
        CryptStat.check_errors = TmpCryptStat.check_errors;
        CryptStat.target_dirs = TmpCryptStat.target_dirs;
        CryptStat.check_files = TmpCryptStat.check_files;
        CryptStat.migration_target = TmpCryptStat.migration_target;

        memset(&TmpCryptStat, 0, sizeof(TmpCryptStat));
    }
}

dgt_sint32 PccCryptDir::filter() throw(DgcExcept) {
    if (Status == PCC_STATUS_TYPE_DELETED || Status == PCC_STATUS_TYPE_PAUSE)
        return 0;
    if (lock() == 0) {
        if (CryptStat.start_time == 0) {
            struct timeval ct;
            gettimeofday(&ct, 0);
            CryptStat.start_time = CryptStat.end_time = ct.tv_sec;
            CryptStat.dir_id = DirID;
            CryptStat.zone_id = CryptZone->zoneID();
            CryptStat.system_id = CryptZone->systemID();
            CryptStat.job_status = Status;

            setTmpDstPath(DstDir && *DstDir ? DstDir : SrcDir);
            if (dirRuleVersion() != 2)
                CryptStat.output_files = countCryptFile(
                    TmpDstPath,
                    CryptZone
                        ->encryptFlag());  // collecting outfiles in destination
                                           // directory for statistic
        }

        struct stat fstat;
        if (stat(SrcDir, &fstat) < 0) {
            unlock();
            THROWnR(DgcOsExcept(errno,
                                new DgcError(SPOS, "stat[%s] failed", SrcDir)),
                    -1);
        }

        setTmpSrcPath(SrcDir);
        setTmpDstPath(DstDir && *DstDir ? DstDir : SrcDir);
        if (CryptMir == 0) CryptMir = new PccCryptMir(fstat.st_ino);
        if (Schedule.isWorkingTime()) {
            CryptMir->openMir();  // added by jhpark 2017.11.21
            switch (dirRuleVersion()) {
                case 1:  // Scoped directory depth filter (crypt)
                    CurrDirDepth = -1;
                    filter1(CryptMir, SrcDir,
                            DstDir && *DstDir ? DstDir : SrcDir, 1);
                    break;

            }
            CryptMir->closeMir();  // added by jhpark 2017.11.21
        }
        CryptStat.filters++;
        unlock();
    }
    return 0;
}

dgt_sint32 PccCryptDir::compileDirPttns(
    DgcBgrammer* bg, dgt_schar* err_string) throw(DgcExcept) {
    if (DirExprs) {
        delete DirExprs;
        DirExprs = 0;
    }
    DirExprs = new PccRegExprList();
    dgt_sint32 expr_no;
    for (expr_no = 1;; expr_no++) {
        dgt_schar* val = 0;
        dgt_sint32 rtn = 0;
        dgt_schar expr_string[32];
        sprintf(expr_string, "dir_pttn.%d", expr_no);
        if ((val = bg->getValue(expr_string)) && *val) {
            dgt_schar tmp_val[129];
            memset(tmp_val, 0, 129);
            if (*val == '*') {
                tmp_val[0] = '.';
                tmp_val[1] = '.';
                strncpy(tmp_val + 2, val, 128);
            } else
                // 2017.07.09 modified by jhpark
                strncpy(tmp_val, val, 128);
            if ((rtn = DirExprs->compileStr(tmp_val, err_string)) < 0) {
                THROWnR(
                    DgcOsExcept(errno, new DgcError(
                                           SPOS, "compileStr[%s] failed", val)),
                    rtn);
            }
        } else {
            break;
        }
    }
    return 0;
}

dgt_sint32 PccCryptDir::compileFilePttns(
    DgcBgrammer* bg, dgt_schar* err_string) throw(DgcExcept) {
    if (FileExprs) {
        delete FileExprs;
        FileExprs = 0;
    }
    FileExprs = new PccRegExprList();
    dgt_sint32 expr_no;
    for (expr_no = 1;; expr_no++) {
        dgt_schar* val = 0;
        dgt_sint32 rtn = 0;
        dgt_schar expr_string[32];
        sprintf(expr_string, "file_pttn.%d", expr_no);
        if ((val = bg->getValue(expr_string)) && *val) {
            dgt_schar tmp_val[129];
            memset(tmp_val, 0, 129);
#if 0
			if (EncryptFlag == 0 && *OutExtension) {
				// add the OutExtension at the end the expression in case of decrypting
				//                 // because the OutExtension was attached when encrypting
				sprintf(tmp_val,"%s[.]%s",val,OutExtension);
			} else {
				strncpy(tmp_val,val,128);
			}
#else
            // added by shson for when first charactor is *
            if (*val == '*') {
                tmp_val[0] = '.';
                tmp_val[1] = '.';
                strncpy(tmp_val + 2, val, 128);
            } else
                // 2017.07.09 modified by jhpark
                strncpy(tmp_val, val, 128);
#endif
            if ((rtn = FileExprs->compileStr(tmp_val, err_string)) < 0) {
                THROWnR(
                    DgcOsExcept(errno, new DgcError(
                                           SPOS, "compileStr[%s] failed", val)),
                    rtn);
            }
        } else {
            break;
        }
    }
    return 0;
}

dgt_sint32 PccCryptDir::isTargetDir(const dgt_schar* src_dir) {
    if (DirExprs == 0) {
        return 1;  // all directory
    }

    regmatch_t pttn_match[1];
    exp_type* preg;
    DirExprs->rewind();
    while ((preg = DirExprs->nextPttn())) {  // each dir pattern
        if (regexec(&preg->reg, src_dir, 1, pttn_match, 0) == 0) {
            //&& (pttn_match[0].rm_eo - pttn_match[0].rm_so) ==
            //(dgt_sint32)strlen(src_dir)) {
            return 1;  // perfect pattern match
        }
    }

    return 0;
}

dgt_sint32 PccCryptDir::isTargetFile(const dgt_schar* src_file) {
    if (FileExprs == 0) {
        return 1;  // all file
    }

    regmatch_t pttn_match[1];
    exp_type* preg;
    FileExprs->rewind();
    while ((preg = FileExprs->nextPttn())) {  // each file pattern
        if (regexec(&preg->reg, src_file, 1, pttn_match, 0) == 0 &&
            (pttn_match[0].rm_eo - pttn_match[0].rm_so) ==
                (dgt_sint32)strlen(src_file)) {
            return 1;
        }
    }

    return 0;
}
