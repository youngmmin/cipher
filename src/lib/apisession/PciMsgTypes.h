/*******************************************************************
 *   File Type          :       type definition
 *   Classes            :       PciMsgTypes.h
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 14
 *   Description        :       petra cipher protocol message type definitions
 *   Modification history
 *   date                  	    modification
 *   18.06.19 by shson		 	add type pc_type_user_file_request_in
--------------------------------------------------------------------

********************************************************************/
#ifndef PCI_MSG_TYPE_H
#define PCI_MSG_TYPE_H

typedef struct {
    dgt_uint32 db_sid;
    dgt_schar instance_name[33];
    dgt_schar db_name[33];
    dgt_schar client_ip[65];
    dgt_schar db_user[33];
    dgt_schar os_user[33];
    dgt_schar client_program[129];
    dgt_uint8 protocol; /* 1->beq, 2->ipc, 3->tcp */
    dgt_schar user_id[33];
    dgt_schar client_mac[65];
} pc_type_open_sess_in;

typedef struct {
    dgt_sint64 user_sid;
    dgt_sint64 virtual_key_id;
    dgt_uint8 crypt_type;
    dgt_uint8 target_type;
    dgt_schar name1[33];
    dgt_schar name2[33];
    dgt_schar name3[33];
    dgt_schar name4[33];
    dgt_schar name5[33];
} pc_type_get_vkey_db_priv_in;

typedef struct {
    dgt_sint64 user_sid;
    dgt_sint64 virtual_key_id;
    dgt_uint8 crypt_type;
    dgt_uint8 target_type;
    dgt_schar name1[65];
    dgt_schar name2[65];
    dgt_schar name3[512];
    dgt_schar name4[129];
} pc_type_get_vkey_file_priv_in;

typedef struct {
    dgt_sint64 user_sid;
    dgt_sint64 enc_col_id;
} pc_type_get_priv_in;

typedef struct {
    dgt_sint64 user_sid;
    dgt_sint64 enc_col_id;
    dgt_sint64 approve_id;
} pc_type_approve_in;

typedef struct {
    dgt_sint64 user_sid;
    dgt_sint64 enc_col_id;
    dgt_sint64 dec_count;
    dgt_sint64 stmt_id;
    dgt_sint64 level_id;
    dgt_uint32 start_date;
    dgt_sint32 sql_type;
    dgt_uint8 dec_no_priv_flag;
    dgt_uint8 op_type; /* 1 -> encrypt no priv, 2 -> decrypt no priv, 3 -> too
                          many decrypt */
    dgt_schar sql_hash[65];
} pc_type_alert_in;

typedef struct {
    dgt_sint64 enc_col_id;
    dgt_sint64 enc_count;
} pc_type_enc_count_in;

typedef struct {
    dgt_sint64 user_sid;
    dgt_sint64 enc_col_id;
    dgt_sint32 err_code;
} pc_type_posting_in;

typedef struct {
    dgt_sint64 user_sid;
    dgt_sint32 auth_fail_code;
} pc_type_open_sess_out;

typedef struct {
    dgt_uint32 enc_length; /* encryption length */
    dgt_uint16 key_size;   /* Key Size in bits, 128, 192, 256, 384(sha only),
                              512(sha only)  */
    dgt_uint8 cipher_type; /* 0:default, 1:'AES', 2:'SEED', 3:'ARIA', 3:'SHA' */
    dgt_uint8 enc_mode;    /* Encrypt Mode, 0:ECB, 1:CBC, 2:CFB, 3:OFB */
    dgt_uint8 iv_type;  /* initial vector type, 0:no iv, 1:random iv, 2:random
                           within predefined iv, 3-7:predefined iv */
    dgt_uint8 n2n_flag; /* null to null flag */
    dgt_uint8 b64_txt_enc_flag; /* base64 text encoding flag */
    dgt_uint8 enc_start_pos;    /* encryption start position */
    dgt_schar mask_char[33];    /* mask character string for selecting with no
                                   privilige */
    dgt_schar char_set[33];     /* character set */
    dgt_uint8 key[64];          /* key */
} pc_type_get_key_out;

typedef struct {
    dgt_sint64 key_id;                /* encryption key id */
    dgt_uint32 max_col_len;           /* max column length */
    dgt_uint32 dec_alt_threshold;     /* decrypt alert threshold */
    dgt_uint32 dec_masking_threshold; /* decrypt alert threshold */
    dgt_uint8 enc_priv;
    dgt_uint8 dec_priv;
    dgt_uint8 enc_no_priv_alert;
    dgt_uint8 dec_no_priv_alert;
    dgt_uint8 auth_fail_enc_priv;
    dgt_uint8 auth_fail_dec_priv;
    dgt_uint8 enc_audit_flag;
    dgt_uint8 dec_audit_flag;
    dgt_uint8 col_type; /* column data type, 1->char, 2->number, 3->date,
                           4->raw, 0->etc */
    dgt_uint8 ophuek_flag;
    dgt_uint8 multibyte_flag;
    dgt_uint8 week_map[12]; /* 0~5: enc week map, 6~11: dec week map */
} pc_type_get_priv_out;

typedef struct {
    dgt_sint64 enc_col_id;
    dgt_sint64 key_id;                /* encryption key id */
    dgt_uint32 max_col_len;           /* max column length */
    dgt_uint32 dec_alt_threshold;     /* decrypt alert threshold */
    dgt_uint32 dec_masking_threshold; /* decrypt alert threshold */
    dgt_uint8 enc_priv;
    dgt_uint8 dec_priv;
    dgt_uint8 enc_no_priv_alert;
    dgt_uint8 dec_no_priv_alert;
    dgt_uint8 auth_fail_enc_priv;
    dgt_uint8 auth_fail_dec_priv;
    dgt_uint8 enc_audit_flag;
    dgt_uint8 dec_audit_flag;
    dgt_uint8 col_type; /* column data type, 1->char, 2->number, 3->date,
                           4->raw, 0->etc */
    dgt_uint8 ophuek_flag;
    dgt_uint8 multibyte_flag;
    dgt_uint8 week_map[12]; /* 0~5: enc week map, 6~11: dec week map */
} pc_type_get_vkey_priv_out;

typedef struct {
    dgt_sint64 user_sid;
    dgt_sint64 enc_col_id;
    dgt_sint64 enc_count;
    dgt_sint64 dec_count;
    dgt_sint64 lapse_time;
    dgt_sint64 stmt_id;
    dgt_sint64 sql_cpu_time;
    dgt_sint64 sql_elapsed_time;
    dgt_uint32 start_date;
    dgt_sint32 sql_type;
    dgt_uint8 enc_no_priv_flag;
    dgt_uint8 dec_no_priv_flag;
    dgt_schar sql_hash[65];
    dgt_schar reserved[33];
} pc_type_log_request_in;

typedef struct {
    dgt_sint64 user_sid;
    dgt_schar system_name[65];
    dgt_schar system_ip[128];
    dgt_schar file_name[256];
    dgt_schar enc_type[32];
    dgt_uint8 mode;
    dgt_schar key_name[130];
    dgt_sint64 file_size;
    dgt_sint64 processed_byte;
    dgt_schar zone_name[130];
    dgt_uint32 enc_start_date;
    dgt_uint32 enc_end_date;
    dgt_schar err_msg[256];
} pc_type_file_request_in;

typedef struct {
    dgt_sint64 ptu_id;
    dgt_schar client_ip[128];
    dgt_schar system_name[65];
    dgt_schar system_ip[128];
    dgt_schar file_name[256];
    dgt_schar enc_type[32];
    dgt_uint8 mode;
    dgt_schar key_name[130];
    dgt_sint64 file_size;
    dgt_sint64 processed_byte;
    dgt_schar zone_name[130];
    dgt_uint32 enc_start_date;
    dgt_uint32 enc_end_date;
    dgt_schar err_msg[256];
} pc_type_user_file_request_in;

typedef struct {
    dgt_sint64 enc_col_id;
    dgt_sint32 src_len;
} pc_type_crypt_in;

typedef struct {
    dgt_uint8 iv_type;  /* initial vector type > 9 */
    dgt_uint16 iv_size; /* iv size in bits, 128, 192, 256, 384(sha only),
                           512(sha only)  */
} pc_type_get_iv_in;

typedef struct {
    dgt_uint16 iv_size; /* iv size in bits, 128, 192, 256, 384(sha only),
                           512(sha only)  */
    dgt_uint8 iv[64];   /* iv */
} pc_type_get_iv_out;

typedef struct {
    dgt_schar key_name[33];
    dgt_schar key[513];
    dgt_uint16 format_no;
} pc_type_put_ext_key_in;

typedef struct {
    dgt_sint64 key_id;
} pc_type_get_trailer_in;

typedef struct {
    dgt_uint8 trailer_size;
    dgt_schar trailer_char[7];
} pc_type_get_trailer_out;

typedef struct {
    dgt_sint64 start_offset;
    dgt_sint64 end_offset;
    dgt_schar expr[1024];
    dgt_schar data[1024];
} pc_type_detect_file_data_in;

typedef struct {
    dgt_sint64 job_id;
    dgt_sint64 dir_id;
    dgt_sint64 file_id;
    dgt_schar system_name[65];
    dgt_schar system_ip[128];
    dgt_schar file_name[2048];
    dgt_sint64 file_size;
    dgt_uint32 file_mtime;
    dgt_uint32 start_date;
    dgt_uint32 end_date;
    dgt_sint64 pttn_num;
    dgt_sint32 is_skipped;
    dgt_schar parameter[1024];
    dgt_schar err_msg[256];
} pc_type_detect_file_request_in;

static const dgt_sint32 PCI_MSG_COMMAND = 1;
static const dgt_sint32 PCI_MSG_OPEN_SESS = 2;
static const dgt_sint32 PCI_MSG_GET_KEY = 3;
static const dgt_sint32 PCI_MSG_GET_PRIV = 4;
static const dgt_sint32 PCI_MSG_GET_ECID = 5;
static const dgt_sint32 PCI_MSG_ENCRYPT = 6;
static const dgt_sint32 PCI_MSG_DECRYPT = 7;
static const dgt_sint32 PCI_MSG_APPROVE = 8;
static const dgt_sint32 PCI_MSG_ALERT = 9;
static const dgt_sint32 PCI_MSG_ENCRYPT_COUPON = 10;
static const dgt_sint32 PCI_MSG_DECRYPT_COUPON = 11;
static const dgt_sint32 PCI_MSG_LOG_REQUEST = 12;
static const dgt_sint32 PCI_MSG_ENC_COUNT = 13;
static const dgt_sint32 PCI_MSG_POSTING = 14;
static const dgt_sint32 PCI_MSG_GET_IV = 15;
static const dgt_sint32 PCI_MSG_GET_TRAILER = 16;
static const dgt_sint32 PCI_MSG_END = 20;

static const dgt_uint8 PCI_ENCRYPT_PRIV = 1;
static const dgt_uint8 PCI_ENCRYPT_PRIV_ERR = 2;

static const dgt_uint8 PCI_DEC_PRIV_DEC = 1;
static const dgt_uint8 PCI_DEC_PRIV_MASK = 2;
static const dgt_uint8 PCI_DEC_PRIV_SRC = 3;
static const dgt_uint8 PCI_DEC_PRIV_ERR = 4;

static const dgt_uint8 PCI_AUDIT_INSERT = 0x01;
static const dgt_uint8 PCI_AUDIT_UPDATE = 0x02;
static const dgt_uint8 PCI_AUDIT_DELETE = 0x04;
static const dgt_uint8 PCI_AUDIT_SELECT = 0x08;
static const dgt_uint8 PCI_AUDIT_OTHERS = 0x10;

static const dgt_sint32 PCI_TYPE_INSERT = 1;
static const dgt_sint32 PCI_TYPE_UPDATE = 2;
static const dgt_sint32 PCI_TYPE_DELETE = 3;
static const dgt_sint32 PCI_TYPE_SELECT = 4;
static const dgt_sint32 PCI_TYPE_OTHERS = 5;

static const dgt_uint8 PCI_CRYPT_OP_ENCRYPT = 1;
static const dgt_uint8 PCI_CRYPT_OP_DECRYPT = 2;

static const dgt_sint32 PCI_CRYPT_COL_LEN = 128;

static const dgt_schar* PCI_DFLT_HASH_COL_NAME = "__default__hash__column__";

static const dgt_sint64 PCI_ENC_LOG_COUNT = 1000000;

#if 1  // added by chchung 2015.9.13 for adding test mode
static const dgt_uint8 PCI_OP_NO_PULL_NO_PUSH = 3;
static const dgt_uint8 PCI_OP_NO_CRYPT = 2;
static const dgt_uint8 PCI_OP_NO_CRYPT_EQUAL_LOAD = 1;
#endif

static const dgt_uint8 PCI_VKEY_CRYPT_TYPE_ENC_DEC = 0;
static const dgt_uint8 PCI_VKEY_CRYPT_TYPE_ENC = 1;
static const dgt_uint8 PCI_VKEY_CRYPT_TYPE_DEC = 2;

static const dgt_uint8 PCI_VKEY_TARGET_TYPE_DB = 1;
static const dgt_uint8 PCI_VKEY_TARGET_TYPE_FILE = 2;

#endif
