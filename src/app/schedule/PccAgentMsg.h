/*******************************************************************
 *   File Type          :       message type declaration
 *   Classes            :
 *   Implementor        :       Jaehun
 *   Create Date        :       2017. 7. 1
 *   Description        :       message type
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_AGENT_MSG_H
#define PCC_AGENT_MSG_H

#include "DgcObject.h"

static const dgt_uint8 PCC_AGENT_TYPE_STATISTIC_JOB = 1;
static const dgt_uint8 PCC_AGENT_TYPE_TEMPORARY_JOB = 2;
static const dgt_uint8 PCC_AGENT_TYPE_STREAM_JOB = 3;
// static const dgt_uint8 PCC_AGENT_TYPE_TEMPORARY_JOB		= 4;	// legacy
static const dgt_uint8 PCC_AGENT_TYPE_DETECT_JOB = 5;

static const dgt_uint8 PCC_STATUS_TYPE_DELETED = 0;
static const dgt_uint8 PCC_STATUS_TYPE_RUN = 1;
static const dgt_uint8 PCC_STATUS_TYPE_PAUSE = 2;
static const dgt_uint8 PCC_STATUS_TYPE_MIGRATION = 3;

static const dgt_uint16 PCC_AGENT_UDS_MSG_TYPE_STOP = 1;
static const dgt_uint16 PCC_AGENT_UDS_MSG_TYPE_STATUS = 2;
static const dgt_uint16 PCC_AGENT_UDS_MSG_TYPE_GET_PID = 3;
static const dgt_uint16 PCC_AGENT_UDS_MSG_TYPE_DETAIL_STATUS = 4;

static const dgt_uint16 PCC_MANAGER_UDS_MSG_TYPE_STOP = 1;
static const dgt_uint16 PCC_MANAGER_UDS_MSG_TYPE_STATUS = 2;
static const dgt_uint16 PCC_MANAGER_UDS_MSG_TYPE_DEATIL_STATUS = 3;

typedef struct {
    dgt_sint64 agent_id;
    dgt_sint64 agent_pid;
    dgt_sint32 max_target_files;
    dgt_sint32 max_use_cores;
    dgt_sint32 num_managers;
    dgt_sint32 num_jobs;
} pcct_agent_status;

typedef struct {
    dgt_sint64 manager_id;
    dgt_sint64 manager_pid;
    dgt_sint32 num_agents;
    dgt_uint32 soha_conn_status;
    dgt_schar primary_soha_svc[33];
    dgt_schar primary_soha_ip[65];
    dgt_sint32 primary_soha_port;
    dgt_schar secondary_soha_svc[33];
    dgt_schar secondary_soha_ip[65];
    dgt_sint32 secondary_soha_port;
} pcct_manager_status;

typedef struct {
    dgt_sint64 agent_id;
    dgt_sint64 last_update;
    dgt_sint32 sess_id;
} pcct_get_agent_info;

typedef struct {
    dgt_sint64 job_id;
    dgt_sint64 last_update;
    dgt_sint32 max_target_files;
    dgt_sint32 collecting_interval;
    dgt_uint8 job_type;
    dgt_uint8 status;
    dgt_schar data[1025];
} pcct_set_params;

typedef struct {
    dgt_schar dir_path[1024];
    dgt_sint64 offset;
    dgt_sint32 fetch_count;
} pcct_dir_entry_in;

typedef struct {
    dgt_sint64 file_id;
    dgt_sint64 dir_id;
    dgt_sint64 zone_id;
    dgt_sint64 file_size;
    dgt_uint32 last_update;
    dgt_uint8 type;  // 1 -> direcroty, 2 -> file
    dgt_uint8 encrypt_flag;
    dgt_schar name[256];
    dgt_sint64 curr_offset;
    dgt_sint32 total_count;
} pcct_dir_entry;

typedef struct {
    dgt_sint64 job_id;
    dgt_sint64 dir_id;
    dgt_sint64 agent_id;
    dgt_sint64 zone_id;
    dgt_sint64 filters;
    dgt_sint64 check_dirs;
    dgt_sint64 check_errors;
    dgt_sint64 target_dirs;
    dgt_sint64 check_files;
    dgt_sint64 target_files;
    dgt_sint64 input_files;
    dgt_sint64 output_files;
    dgt_sint64 crypt_errors;
    dgt_sint64 used_cores;
    dgt_sint64 used_micros;
    dgt_sint64 input_bytes;
    dgt_sint64 output_bytes;
    dgt_sint64 system_id;
    dgt_uint32 start_time;
    dgt_uint32 end_time;
    dgt_sint32 job_status;
    dgt_sint32 dir_status;
    dgt_sint64 migration_target;
    dgt_sint64 reserved;
} pcct_crypt_stat;

typedef struct {
    dgt_sint64 job_id;
    dgt_sint64 enc_zone_id;
    dgt_sint64 dir_id;
} pcct_get_dir_crypt_stat;

typedef struct {
    dgt_sint64 ptu_id;
    dgt_sint64 enc_zone_id;
    dgt_uint8 crypt_flag;
    dgt_schar client_ip[128];
    dgt_schar in_file_name[2049];
    dgt_schar out_file_name[2049];
} pcct_crypt_file_in;

typedef struct {
    dgt_sint32 rtn_code;
    dgt_schar error_message[1025];
} pcct_crypt_file_out;

typedef struct {
    dgt_sint64 ptu_id;
    dgt_schar client_ip[128];
    dgt_schar validation_file_path[2049];
} pcct_validation_file_in;

typedef struct {
    dgt_sint64 agent_id;
    dgt_sint64 job_id;
    dgt_uint8 target_type;
} pcct_target_list_in;

typedef struct {
    dgt_sint64 job_id;
    dgt_sint64 enc_zone_id;
    dgt_sint64 dir_id;
    dgt_schar in_file_name[2049];
    dgt_schar out_file_name[2049];
    dgt_uint32 input_time;
    dgt_sint32 error_code;
    dgt_schar error_msg[1025];
} pcct_target_list_out;

typedef struct {
    dgt_sint64 agent_id;
    dgt_sint64 job_id;
    dgt_sint64 dir_id;
} pcct_recollect_crypt_dir_in;

typedef struct {
    dgt_sint32 rtn_code;
    dgt_schar error_message[1025];
} pcct_recollect_crypt_dir_out;

typedef struct {
    dgt_sint64 job_id;
} pcct_fp_get_stat_in;

typedef struct {
    dgt_sint64 job_id;
    dgt_sint64 transed_files;
    dgt_sint64 trans_missed_files;
    dgt_sint64 transed_bytes;
    dgt_sint64 fp_files;
    dgt_sint64 non_fp_files;
    dgt_sint64 masked_fp_files;
    dgt_sint64 mask_missed_fp_files;
} pcct_fp_get_stat_out;

typedef struct {
    dgt_schar dir_path[2048];
    dgt_schar file_name[256];
    dgt_uint8 status_value;
} pcct_fp_set_userstatus_in;

typedef struct {
    dgt_schar dir_path[2048];
    dgt_schar file_name[256];
    dgt_schar dst_path[2048];
    dgt_sint32 tl_x;
    dgt_sint32 tl_y;
    dgt_sint32 tr_x;
    dgt_sint32 tr_y;
    dgt_sint32 bl_x;
    dgt_sint32 bl_y;
    dgt_sint32 br_x;
    dgt_sint32 br_y;
} pcct_fp_usermasking_in;

typedef struct {
    dgt_sint32 rtn;
    dgt_schar err_msg[256];
} pcct_fp_rtn_out;

typedef struct {
    dgt_schar dir_path[1024];
    dgt_sint64 offset;
    dgt_sint32 fetch_count;
    dgt_sint32 fpstatus;
} pcct_fp_dir_entry_in;

typedef struct {
    dgt_sint64 file_id;
    dgt_sint64 dir_id;
    dgt_sint64 zone_id;
    dgt_sint64 file_size;
    dgt_uint32 last_update;
    dgt_uint8 type;  // 1 -> direcroty, 2 -> file
    dgt_uint8 encrypt_flag;
    dgt_schar name[256];
    dgt_sint64 curr_offset;
    dgt_sint32 total_count;
    dgt_sint32 total_page;
    dgt_schar fp_point[1024];
} pcct_fp_dir_entry;

typedef struct {
    dgt_schar file_name[2048];
    dgt_schar parameter[1024];
} pcct_detect_info_in;

typedef struct {
    dgt_sint64 start_offset;
    dgt_sint64 end_offset;
    dgt_sint32 data_seq;
    dgt_schar expr[1024];
    dgt_schar data[1024];
} pcct_detect_info_out;

typedef struct {
    dgt_schar file_name[2048];
    dgt_sint64 file_size;
    dgt_uint32 file_mtime;
} pcct_verify_detect_info_in;

typedef struct {
    dgt_sint32 rtn_code;
    dgt_schar error_message[1025];
} pcct_verify_detect_info_out;

typedef struct {
    dgt_sint64 agent_id;
    dgt_sint64 job_id;
    dgt_sint64 file_id;
    dgt_sint32 file_type;
    dgt_sint32 fetch_count;
} pcct_get_stream_stat_in;

typedef struct {
    dgt_sint64 file_id;
    dgt_sint64 dir_id;
    dgt_sint64 enc_zone_id;
    dgt_sint64 in_file_size;
    dgt_sint64 out_file_size;
    dgt_uint32 lm_time;
    dgt_schar in_file_name[2049];
    dgt_schar out_file_name[2049];
    dgt_sint32 error_code;
    dgt_schar error_msg[1025];
    dgt_sint64 job_id;
    dgt_sint32 total_count;
} pcct_get_stream_stat_out;

#endif
