/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccPcfsMsg
 *   Implementor        :       Jaehun
 *   Create Date        :       2018. 7. 17
 *   Description        :       pcfs messages
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_PCFS_MSG_H
#define PCC_PCFS_MSG_H

#include "DgcObject.h"

typedef struct {
    dgt_uint16 pcfs_id;
    dgt_schar name[33];
    dgt_schar root_dir[257];
    dgt_schar mount_dir[257];
    dgt_schar device[33];
    dgt_schar auto_mount[11];
    dgt_schar status[11];
} pcfst_fs_list;

typedef struct {
    dgt_uint16 pcfs_id;
    dgt_uint16 mount_type;  // 1 -> mount, 2 -> unmount
} pcfst_mount_rqst;

typedef struct {
    dgt_uint16 pcfs_id;
    dgt_sint64 encrypt_files;
    dgt_sint64 decrypt_files;
    dgt_sint64 pass_files;
    dgt_sint64 encrypt_calls;
    dgt_sint64 decrypt_calls;
    dgt_sint64 pass_read_calls;
    dgt_sint64 pass_write_calls;
    dgt_sint64 encrypt_bytes;
    dgt_sint64 decrypt_bytes;
    dgt_sint64 pass_read_bytes;
    dgt_sint64 pass_write_bytes;
    dgt_sint64 all_calls;
    dgt_sint64 start_time;
    dgt_sint64 pid;
} pcfst_fs_stat;

#endif
