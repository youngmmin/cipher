#include "PcaSessionPool.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "postgres.h"
#include "fmgr.h"

void post_logger(const char *fmt, ...)
{
    FILE*       fp;

    if (fmt == NULL) return;
    fp=(FILE*)fopen("/tmp/post_cipher.log","a");
    if (fp == NULL) return;
    va_list argptr;
    va_start(argptr, fmt);
    vfprintf(fp, fmt, argptr);
    va_end(argptr);
    fflush(fp);
    fclose(fp);
    return;
}


#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

dgt_sint32 db_sid=-1;

dgt_sint32 clib_sessinfo()
{
        PcaSession*     session=PcaSessionPool::openSession(1);
        if (!session) return -1;
        dgt_sint32 rtn=session->openSession(1, "pgsql", "pgsql", "127.0.0.1", "dbuser","os_user", "pgm", 1, " ", " ");
	return rtn;
}

PG_FUNCTION_INFO_V1(pca_encrypt);

Datum pca_encrypt(PG_FUNCTION_ARGS)
{
	if (PG_ARGISNULL(0)) {
		PG_RETURN_NULL();
	}
	text* src_data = PG_GETARG_TEXT_P(0);
	text* enc_col_name = PG_GETARG_TEXT_P(1);

	if (db_sid == -1) {
		dgt_sint32 rtn=clib_sessinfo();
		if (rtn < 0) {
	            ereport(ERROR,
                    (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                     errmsg("Petra open session failed")));
		} else {
			db_sid=rtn;
		}
	}
	PcaSession*     session=PcaSessionPool::getSession(db_sid);
        if (!session) {
            ereport(ERROR,
	    (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
	     errmsg("Petra getSession failed")));
        }
        dgt_uint32      dst_len = 0;
        dgt_uint8*      dst = 0;
	dgt_schar	enc_col_nm[256];
	memset(enc_col_nm,0,256);
	memcpy(enc_col_nm, (void*) VARDATA(enc_col_name), VARSIZE(enc_col_name) - VARHDRSZ);
        if (session->encrypt((dgt_schar*)enc_col_nm, (dgt_uint8*) VARDATA(src_data), VARSIZE(src_data)-VARHDRSZ, &dst, &dst_len) < 0) {
                //
                // encrypt failed, session has this last error code which can be gotten by ECODE
                //
		ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                errmsg("Petra encryption failed")));
        }
	text* enc_data = (text *) palloc(dst_len + VARHDRSZ);
	SET_VARSIZE(enc_data,dst_len + VARHDRSZ);
	memcpy((void *) VARDATA(enc_data), /* destination */
		(void *) dst,     /* source */
		dst_len);  /* how many bytes */
	PG_RETURN_TEXT_P(enc_data);
}

PG_FUNCTION_INFO_V1(pca_decrypt);

Datum pca_decrypt(PG_FUNCTION_ARGS)
{
	if (PG_ARGISNULL(0)) {
		PG_RETURN_NULL();
	}
	text* src_data = PG_GETARG_TEXT_P(0);
	text* enc_col_name = PG_GETARG_TEXT_P(1);

	if (db_sid == -1) {
		dgt_sint32 rtn=clib_sessinfo();
		if (rtn < 0) {
	            ereport(ERROR,
                    (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                     errmsg("Petra open session failed")));
		} else {
			db_sid=rtn;
		}
	}
	PcaSession*     session=PcaSessionPool::getSession(db_sid);
        if (!session) {
            ereport(ERROR,
	    (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
	     errmsg("Petra getSession failed")));
        }
        dgt_uint32      dst_len = 0;
        dgt_uint8*      dst = 0;
	dgt_schar	enc_col_nm[256];
	memset(enc_col_nm,0,256);
	memcpy(enc_col_nm, (void*) VARDATA(enc_col_name), VARSIZE(enc_col_name) - VARHDRSZ);
        if (session->decrypt((dgt_schar*)enc_col_nm, (dgt_uint8*) VARDATA(src_data), VARSIZE(src_data)-VARHDRSZ, &dst, &dst_len) < 0) {
                //
                // decrypt failed, session has this last error code which can be gotten by ECODE
                //
		ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                errmsg("Petra decryption failed")));
        }
	text* dec_data = (text *) palloc(dst_len + VARHDRSZ);
	SET_VARSIZE(dec_data,dst_len + VARHDRSZ);
	memcpy((void *) VARDATA(dec_data), /* destination */
		(void *) dst,     /* source */
		dst_len);  /* how many bytes */
	PG_RETURN_TEXT_P(dec_data);
}

#ifdef __cplusplus
}
#endif
