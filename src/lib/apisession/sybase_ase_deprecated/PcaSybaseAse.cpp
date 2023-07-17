/*
** Confidential property of Sybase, Inc.
** (c) Copyright, Inc. 1985 to 1996
** All rights reserved
*/

/*
**
** xp_echo.c
**
**	Description:
**		The following sample program is generic in nature. It 
**		echoes an input string which is passed as the first parameter 
**		to the xp_echo ESP. This string is retrieved into a buffer 
**		and then sent back (echoed) to the ESP client. The purpose of
**		this program is to provide a template for the user to 
**		build an ESP.
**
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#if	!MACOSX
#include <malloc.h>
#endif	/* !MACOSX */

/*
** Required Open Server include files.
*/
#if 1
#include "ospublic.h"
#include "oserror.h"
#else
#include "./sybase_ase_15.5/ospublic.h"
#include "./sybase_ase_15.5/oserror.h"
#endif

/*
** Constant defining the length of the buffer that receives the input string.
** All of the SQL Server parameters related to ESP must be max 255 char long.
*/
#define BUF_LEN	255

#include "PciCryptoIf.h"

static const dgt_uint8  test_key[32]=
{
185,
127,
59,
99,
81,
116,
20,
119,
14,
21,
80,
143,
17,
60,
52,
106,
69,
158,
26,
6,
252,
183,
74,
42,
254,
23,
87,
37,
152,
118,
138,
206
};

#if 0
static const dgt_uint8  test_key2[64]=
{
123,8 ,94,71,230, 9,12, 70, 95,71,
84 ,84, 3,78,  5,63, 4, 83,123,95,
47 ,56,91,34,123,46,73,214, 38,24,
  1,239,
  1,239,
84 ,84, 3,78,  5,63, 4, 83,123,95,
47 ,56,91,34,123,46,73,214, 38,24,
123,8 ,94,71,230, 9,12, 70, 95,71
};
#endif


static PCI_Context ctx;
static PCI_Context ctx2;
static int init_flag=0;

void logger(const char *fmt, ...)
{
    FILE*       fp;

    if (fmt == NULL) return;
    fp=(FILE*)fopen("/tmp/ase.log","a");
    if (fp == NULL) return;
    va_list argptr;
    va_start(argptr, fmt);
    vfprintf(fp, fmt, argptr);
    va_end(argptr);
    fflush(fp);
    fclose(fp);
    return;
}


extern "C"
{
CS_INT sybesp_dll_version()
{
	return CS_CURRENT_VERSION;
}
/*
** Function:
**	xp_message
**	Purpose: Sends information, status and completion of the command
** 	to the server.
** Input:
**	SRV_PROC *
**	char *	a message string.
** Output:
**	void
**
*/
void xp_message
(
	SRV_PROC	*srvproc,	/* 
					** Pointer to Open Server thread 
					** control structure 
					*/
	const char	*message_string	/* Input message string */
)
{
	/* 
	** Declare a variable that will contain information about the
	** message being sent to the SQL client.
	*/
	CS_SERVERMSG	*errmsgp;

	/*
	** Allocate memory for this variable.
	*/
	errmsgp = (CS_SERVERMSG *) malloc((CS_INT) sizeof(CS_SERVERMSG));
	if (errmsgp == NULL)
		return;
	/*
	** clean the structure
	*/
	memset(errmsgp,(CS_INT)0,(CS_INT) sizeof(CS_SERVERMSG)); 

	/*
	** Put your number in as the message number
	*/
	errmsgp->msgnumber = 25000;

	errmsgp->state = 0;

	/*
	** The message is purely informational
	*/
	errmsgp->severity = SRV_FATAL_SERVER;

	/*
	** Let's copy the string over.
	*/
	errmsgp->textlen = strlen(message_string);
	if (errmsgp->textlen >= CS_MAX_MSG )
		return;
	strncpy(errmsgp->text, message_string, errmsgp->textlen);
	errmsgp->status = (CS_FIRST_CHUNK | CS_LAST_CHUNK);

	srv_sendinfo(srvproc, errmsgp, CS_TRAN_UNDEFINED);

	/* Send the status to the client. */
	srv_sendstatus(srvproc, 1);

	/*
	** A SRV_DONE_MORE instead of a SRV_DONE_FINAL must complete the
	** result set of an Extended Stored Procedure.
	*/
	srv_senddone(srvproc, SRV_DONE_MORE, 0, 0);

	free(errmsgp);
}

#ifdef _WINNT
CS_RETCODE __stdcall pls_encrypt_proc( SRV_PROC        *srvproc)
#else
/*	unix version */
CS_RETCODE pls_encrypt_proc(SRV_PROC	*srvproc)
#endif
{
	if (init_flag == 0) {
		PCI_initContext(&ctx, test_key, 256, PCI_CIPHER_ARIA, 2, PCI_IVT_NO, 1, 2, 1, 0, 0);
		PCI_initContext(&ctx2, test_key, 256, PCI_CIPHER_SHA, 0, PCI_IVT_NO, 1, 2, 1);
		init_flag=1;
	}
	CS_INT		paramnum;	/* number of parameters */
	CS_CHAR		src[BUF_LEN + 1]; 
	memset(src,0,BUF_LEN+1);
	CS_CHAR		enc_col_id[256];
	memset(enc_col_id,0,256);
	CS_RETCODE	result = CS_SUCCEED;
	CS_DATAFMT	paramfmt;	/* input/output param format */
	CS_DATAFMT	paramfmt2;	/* input/output param format */
	CS_INT		src_len;		/* Length of input param */
	CS_SMALLINT	outlen;
	CS_INT		len2;		/* Length of input param */
	CS_SMALLINT	outlen2;
	
	/*
	** Get number of input parameters
	*/
	srv_numparams(srvproc, &paramnum);

	/*
	** Only one parameter is expected.
	*/
	if (paramnum != 3)
	{
		/*
		** Send a usage error message
		*/
		xp_message(srvproc, "Invalid number of parameters");
		result = CS_FAIL;
	}
	else
	{
		/*
		** Perform initializations.
		*/
		outlen = CS_GOODDATA;
		outlen2 = CS_GOODDATA;
		memset(&paramfmt, (CS_INT)0, (CS_INT)sizeof(CS_DATAFMT));
		memset(&paramfmt2, (CS_INT)0, (CS_INT)sizeof(CS_DATAFMT));

		/*
		** We are receiving data through an ESP as the first parameter. 
		** So describe this expected parameter.
		*/
		if ((result == CS_SUCCEED) &&
			srv_descfmt(srvproc, CS_GET, SRV_RPCDATA, 1, &paramfmt)
				!= CS_SUCCEED)
		{
			result = CS_FAIL;
		}

		/*
		** Describe and bind the buffer to receive the parameter.
		*/
		if ((result == CS_SUCCEED) &&
			(srv_bind(srvproc, CS_GET, SRV_RPCDATA, 1, &paramfmt,
			(CS_BYTE *) src, &src_len, &outlen) != CS_SUCCEED))
		{
			result = CS_FAIL;
		}

#if 0
		/*
		** Receive the expected data.
		*/
		if ((result == CS_SUCCEED) &&
			srv_xferdata(srvproc,CS_GET,SRV_RPCDATA) != CS_SUCCEED)
		{
			result = CS_FAIL;
		}
#endif

		/*
		** We are receiving data through an ESP as the second parameter. 
		** So describe this expected parameter.
		*/
                if ((result == CS_SUCCEED) &&
                        srv_descfmt(srvproc, CS_GET, SRV_RPCDATA, 2, &paramfmt2)
                                != CS_SUCCEED)
                {
                        result = CS_FAIL;
                }

                /*
                ** Describe and bind the buffer to receive the parameter.
                */
                if ((result == CS_SUCCEED) &&
                        (srv_bind(srvproc, CS_GET, SRV_RPCDATA, 2, &paramfmt2,
                        (CS_BYTE *) enc_col_id, &len2, &outlen2) != CS_SUCCEED))
                {
                        result = CS_FAIL;
                }

                /*
                ** Receive the expected data.
                */
                if ((result == CS_SUCCEED) &&
                        srv_xferdata(srvproc,CS_GET,SRV_RPCDATA) != CS_SUCCEED)
                {
                        result = CS_FAIL;
                }
		/* 
		** Now we have the input info and are ready to send the
		** output info.
		*/
		if (result == CS_SUCCEED)
		{
			/*
			** Perform initialization.
			*/
			if (src_len == 0)
				outlen = CS_NULLDATA;
			else
				outlen = CS_GOODDATA;

			memset(&paramfmt,(CS_INT)0,(CS_INT)sizeof(CS_DATAFMT));
			strcpy(paramfmt.name, "pls_encrypt_proc");
			paramfmt.namelen = CS_NULLTERM;
			paramfmt.datatype = CS_CHAR_TYPE;
		//	paramfmt.format = CS_FMT_NULLTERM;
			paramfmt.locale = (CS_LOCALE *) NULL;
			paramfmt.status |= CS_CANBENULL;
			paramfmt.status |= CS_RETURN;
			paramfmt.maxlength = BUF_LEN;

			dgt_sint32 ret=0;
			CS_INT dst_len = 255;
			dgt_char  dst[256];
			memset(dst,0,256);
			if (!strncasecmp((char*)enc_col_id,"dbo.VIMS_KEY.PASSWORD",21)) {
				if((ret=PCI_encrypt(&ctx2, (dgt_uint8*)src, src_len, (dgt_uint8*)dst, (dgt_uint32*)&dst_len)) < 0) {
					result=CS_FAIL;
				}  
			} else {
				if((ret=PCI_encrypt(&ctx, (dgt_uint8*)src, src_len, (dgt_uint8*)dst, (dgt_uint32*)&dst_len)) < 0) {
					result=CS_FAIL;
				}	
			}
			/*
			** Describe the data that is being sent.
			*/
			if ((result == CS_SUCCEED) &&
				srv_descfmt(srvproc, CS_SET, SRV_RPCDATA, 
					1, &paramfmt) != CS_SUCCEED)
			{
				result = CS_FAIL;
			}
			/*
			** Describe and bind the buffer that contains the data
			** to be sent.
			*/
			if ((result == CS_SUCCEED) &&
				(srv_bind(srvproc, CS_SET, SRV_RPCDATA, 1, 
				&paramfmt, (CS_BYTE *) dst, &dst_len, 
				&outlen) != CS_SUCCEED))
			{
				result = CS_FAIL;
			}

			/*
			** Send the actual data.
			*/
			if ((result == CS_SUCCEED) &&
				srv_xferdata(srvproc, CS_SET, SRV_RPCDATA) 
						!= CS_SUCCEED)
			{
				result = CS_FAIL;
			}
		}

		/*
		** Indicate to the ESP client how the transaction was performed
		*/ 
		if (result == CS_FAIL)
			srv_sendstatus(srvproc, 1);
		else
			srv_sendstatus(srvproc, 0);

		/*
		** Send a count of the number of rows sent to the client.
		*/
		srv_senddone(srvproc,(SRV_DONE_COUNT | SRV_DONE_MORE), 0, 1);

	}

	return result;
}
#ifdef _WINNT
CS_RETCODE __stdcall pls_decrypt_proc( SRV_PROC        *srvproc)
#else
/*      unix version */
CS_RETCODE pls_decrypt_proc(SRV_PROC  *srvproc)
#endif
{
        if (init_flag == 0) {
                PCI_initContext(&ctx, test_key, 256, PCI_CIPHER_ARIA, 2, PCI_IVT_NO, 1, 2, 1, 0, 0);
                PCI_initContext(&ctx2, test_key, 256, PCI_CIPHER_SHA, 0, PCI_IVT_NO, 1, 2, 1);
                init_flag=1;
        }
        CS_INT          paramnum;       /* number of parameters */
        CS_CHAR         src[BUF_LEN + 1];
	memset(src,0,BUF_LEN+1);
        CS_CHAR         enc_col_id[256];
	memset(enc_col_id,0,256);
        CS_RETCODE      result = CS_SUCCEED;
        CS_DATAFMT      paramfmt;       /* input/output param format */
        CS_DATAFMT      paramfmt2;      /* input/output param format */
        CS_INT          src_len;                /* Length of input param */
        CS_SMALLINT     outlen;
        CS_INT          len2;           /* Length of input param */
        CS_SMALLINT     outlen2;

        /*
        ** Get number of input parameters
        */
        srv_numparams(srvproc, &paramnum);

        /*
        ** Only one parameter is expected.
        */
        if (paramnum != 3)
        {
                /*
                ** Send a usage error message
                */
                xp_message(srvproc, "Invalid number of parameters");
                result = CS_FAIL;
        }
        else
        {
                /*
                ** Perform initializations.
                */
                outlen = CS_GOODDATA;
                outlen2 = CS_GOODDATA;
                memset(&paramfmt, (CS_INT)0, (CS_INT)sizeof(CS_DATAFMT));
                memset(&paramfmt2, (CS_INT)0, (CS_INT)sizeof(CS_DATAFMT));

                /*
                ** We are receiving data through an ESP as the first parameter.
                ** So describe this expected parameter.
                */
                if ((result == CS_SUCCEED) &&
                        srv_descfmt(srvproc, CS_GET, SRV_RPCDATA, 1, &paramfmt)
                                != CS_SUCCEED)
                {
                        result = CS_FAIL;
                }

                /*
                ** Describe and bind the buffer to receive the parameter.
                */
                if ((result == CS_SUCCEED) &&
                        (srv_bind(srvproc, CS_GET, SRV_RPCDATA, 1, &paramfmt,
                        (CS_BYTE *) src, &src_len, &outlen) != CS_SUCCEED))
                {
                        result = CS_FAIL;
                }

#if 0
                /*
                ** Receive the expected data.
                */
                if ((result == CS_SUCCEED) &&
                        srv_xferdata(srvproc,CS_GET,SRV_RPCDATA) != CS_SUCCEED)
                {
                        result = CS_FAIL;
                }
#endif

                /*
                ** We are receiving data through an ESP as the second parameter.
                ** So describe this expected parameter.
                */
                if ((result == CS_SUCCEED) &&
                        srv_descfmt(srvproc, CS_GET, SRV_RPCDATA, 2, &paramfmt2)
                                != CS_SUCCEED)
                {
                        result = CS_FAIL;
                }

                /*
                ** Describe and bind the buffer to receive the parameter.
                */
                if ((result == CS_SUCCEED) &&
                        (srv_bind(srvproc, CS_GET, SRV_RPCDATA, 2, &paramfmt2,
                        (CS_BYTE *) enc_col_id, &len2, &outlen2) != CS_SUCCEED))
                {
                        result = CS_FAIL;
                }
                /*
                ** Receive the expected data.
                */
                if ((result == CS_SUCCEED) &&
                        srv_xferdata(srvproc,CS_GET,SRV_RPCDATA) != CS_SUCCEED)
                {
                        result = CS_FAIL;
                }
                /*
                ** Now we have the input info and are ready to send the
                ** output info.
                */
                if (result == CS_SUCCEED)
                {
                        /*
                        ** Perform initialization.
                        */
                        if (src_len == 0)
                                outlen = CS_NULLDATA;
                        else
                                outlen = CS_GOODDATA;

                        memset(&paramfmt,(CS_INT)0,(CS_INT)sizeof(CS_DATAFMT));
                        strcpy(paramfmt.name, "pls_decrypt_proc");
                        paramfmt.namelen = CS_NULLTERM;
                        paramfmt.datatype = CS_CHAR_TYPE;
 //                       paramfmt.format = CS_FMT_NULLTERM;
                        paramfmt.maxlength = BUF_LEN;
                        paramfmt.locale = (CS_LOCALE *) NULL;
                        paramfmt.status |= CS_CANBENULL;
                        paramfmt.status |= CS_RETURN;

                        dgt_sint32 ret=0;
                        CS_INT dst_len = 255;
                        dgt_char  dst[256];
                        memset(dst,0,256);
                        if (!strncasecmp((char*)enc_col_id,"dbo.VIMS_KEY.PASSWORD",21)) {
                                if((ret=PCI_decrypt(&ctx2, (dgt_uint8*)src, src_len, (dgt_uint8*)dst, (dgt_uint32*)&dst_len)) < 0) {
                                        result=CS_FAIL;
                                }
                        } else {
                                if((ret=PCI_decrypt(&ctx, (dgt_uint8*)src, src_len, (dgt_uint8*)dst, (dgt_uint32*)&dst_len)) < 0) {
                                        result=CS_FAIL;
                                }
                        }
                        /*
                        ** Describe the data that is being sent.
                        */
                        if ((result == CS_SUCCEED) &&
                                srv_descfmt(srvproc, CS_SET, SRV_RPCDATA,
                                        1, &paramfmt) != CS_SUCCEED)
                        {
                                result = CS_FAIL;
                        }

                        /*
                        ** Describe and bind the buffer that contains the data
                        ** to be sent.
                        */
                        if ((result == CS_SUCCEED) &&
                                (srv_bind(srvproc, CS_SET, SRV_RPCDATA, 1,
                                &paramfmt, (CS_BYTE *) dst, &dst_len,
                                &outlen) != CS_SUCCEED))
                        {
                                result = CS_FAIL;
                        }

                        /*
                        ** Send the actual data.
                        */
                        if ((result == CS_SUCCEED) &&
                                srv_xferdata(srvproc, CS_SET, SRV_RPCDATA)
                                                != CS_SUCCEED)
                        {
                                result = CS_FAIL;
                        }
                }

                /*
                ** Indicate to the ESP client how the transaction was performed
                */
                if (result == CS_FAIL)
                        srv_sendstatus(srvproc, 1);
                else
                        srv_sendstatus(srvproc, 0);

                /*
                ** Send a count of the number of rows sent to the client.
                */
                srv_senddone(srvproc,(SRV_DONE_COUNT | SRV_DONE_MORE), 0, 1);

        }

        return result;
}

#if 0
#include "PcaSessionPool.h"
static const int PcAPI_ERR_INVALID_SID             =       -30302;
static int sid=0;

#ifdef _WINNT
CS_RETCODE __stdcall pls_encrypt_b64_id_proc( SRV_PROC        *srvproc)
#else
/*      unix version */
CS_RETCODE pls_encrypt_b64_id_proc(SRV_PROC    *srvproc)
#endif
{
        CS_INT          paramnum;       /* number of parameters */
        CS_CHAR         src[BUF_LEN + 1];
        CS_CHAR         enc_col_id[255];
	memset(enc_col_id,0,255);
        CS_RETCODE      result = CS_SUCCEED;
        CS_DATAFMT      paramfmt;       /* input/output param format */
        CS_DATAFMT      paramfmt2;      /* input/output param format */
        CS_INT          src_len;                /* Length of input param */
        CS_SMALLINT     outlen;
        CS_INT          len2;           /* Length of input param */
        CS_SMALLINT     outlen2;

        /*
        ** Get number of input parameters
        */
        srv_numparams(srvproc, &paramnum);

        /*
        ** Only one parameter is expected.
        */
        if (paramnum != 3) {
                /*
                ** Send a usage error message
                */
                xp_message(srvproc, "Invalid number of parameters");
                result = CS_FAIL;
        } else {
                /*
                ** Perform initializations.
                */
		if (sid == 0) {
			PcaSession*     session=PcaSessionPool::openSession(1);
			if (!session) {
				xp_message(srvproc, "openSession failed\n");
				result = CS_FAIL;
			}
			sid=session->openSession(1, "sybasease", "sybasease", "127.0.0.1", "db_user", "os_user", "pgm", 1, "id", "mac");
		}
                outlen = CS_GOODDATA;
                outlen2 = CS_GOODDATA;
                memset(&paramfmt, (CS_INT)0, (CS_INT)sizeof(CS_DATAFMT));
                memset(&paramfmt2, (CS_INT)0, (CS_INT)sizeof(CS_DATAFMT));
                /*
                ** We are receiving data through an ESP as the first parameter.
                ** So describe this expected parameter.
                */
                if ((result == CS_SUCCEED) &&
                        srv_descfmt(srvproc, CS_GET, SRV_RPCDATA, 1, &paramfmt)
                                != CS_SUCCEED) {
                        result = CS_FAIL;
                }

                /*
                ** Describe and bind the buffer to receive the parameter.
                */
                if ((result == CS_SUCCEED) &&
                        (srv_bind(srvproc, CS_GET, SRV_RPCDATA, 1, &paramfmt,
                        (CS_BYTE *) src, &src_len, &outlen) != CS_SUCCEED)) {
                        result = CS_FAIL;
                }
                if ((result == CS_SUCCEED) &&
                        srv_descfmt(srvproc, CS_GET, SRV_RPCDATA, 2, &paramfmt2)
                                != CS_SUCCEED) {
                        result = CS_FAIL;
                }

                /*
                ** Describe and bind the buffer to receive the parameter.
                */
                if ((result == CS_SUCCEED) &&
                        (srv_bind(srvproc, CS_GET, SRV_RPCDATA, 2, &paramfmt2,
                        (CS_BYTE *) enc_col_id, &len2, &outlen2) != CS_SUCCEED)) {
                        result = CS_FAIL;
                }

                /*
                ** Receive the expected data.
                */
                if ((result == CS_SUCCEED) &&
                        srv_xferdata(srvproc,CS_GET,SRV_RPCDATA) != CS_SUCCEED) {
                        result = CS_FAIL;
                }
                /*
                ** Now we have the input info and are ready to send the
                ** output info.
                */
                if (result == CS_SUCCEED) {
                        /*
                        ** Perform initialization.
                        */
                        if (src_len == 0)
                                outlen = CS_NULLDATA;
                        else
                                outlen = CS_GOODDATA;

                        memset(&paramfmt,(CS_INT)0,(CS_INT)sizeof(CS_DATAFMT));
                        strcpy(paramfmt.name, "pls_encrypt_b64_id_proc");
                        paramfmt.namelen = CS_NULLTERM;
                        paramfmt.datatype = CS_CHAR_TYPE;
                        paramfmt.maxlength = BUF_LEN;
                        paramfmt.locale = (CS_LOCALE *) NULL;
                        paramfmt.status |= CS_CANBENULL;
                        paramfmt.status |= CS_RETURN;

                        dgt_sint32 ret=0;
                        CS_INT dst_len = 255;
                        dgt_char  dst[256];
                        memset(dst,0,256);
			dgt_sint32 col_id=strtol(enc_col_id, NULL, 10);
		        PcaSession*     session=PcaSessionPool::getSession(1);
		        if (!session) {
				xp_message(srvproc, "getSession failed\n");
				result = CS_FAIL;
			}
			if (session->encrypt(col_id, (dgt_uint8*)src, src_len, (dgt_uint8*)dst, (dgt_uint32*)&dst_len) < 0) {
				xp_message(srvproc, "encrypt failed\n");
				result = CS_FAIL;
		        }
                        /*
                        ** Describe the data that is being sent.
                        */
                        if ((result == CS_SUCCEED) &&
                                srv_descfmt(srvproc, CS_SET, SRV_RPCDATA,
                                        1, &paramfmt) != CS_SUCCEED)
                        {
                                result = CS_FAIL;
                        }
                        if ((result == CS_SUCCEED) &&
                                (srv_bind(srvproc, CS_SET, SRV_RPCDATA, 1,
                                &paramfmt, (CS_BYTE *) dst, &dst_len,
                                &outlen) != CS_SUCCEED))
                        {
                                result = CS_FAIL;
                        }

                        /*
                        ** Send the actual data.
                        */
                        if ((result == CS_SUCCEED) &&
                                srv_xferdata(srvproc, CS_SET, SRV_RPCDATA)
                                                != CS_SUCCEED)
                        {
                                result = CS_FAIL;
                        }
                }

                /*
                ** Indicate to the ESP client how the transaction was performed
                */
                if (result == CS_FAIL)
                        srv_sendstatus(srvproc, 1);
                else
                        srv_sendstatus(srvproc, 0);

                /*
                ** Send a count of the number of rows sent to the client.
                */
                srv_senddone(srvproc,(SRV_DONE_COUNT | SRV_DONE_MORE), 0, 1);

        }
        return result;
}

#ifdef _WINNT
CS_RETCODE __stdcall pls_decrypt_b64_id_proc( SRV_PROC        *srvproc)
#else
/*      unix version */
CS_RETCODE pls_decrypt_b64_id_proc(SRV_PROC    *srvproc)
#endif
{
        CS_INT          paramnum;       /* number of parameters */
        CS_CHAR         src[BUF_LEN + 1];
        CS_CHAR         enc_col_id[255];
        memset(enc_col_id,0,255);
        CS_RETCODE      result = CS_SUCCEED;
        CS_DATAFMT      paramfmt;       /* input/output param format */
        CS_DATAFMT      paramfmt2;      /* input/output param format */
        CS_INT          src_len;                /* Length of input param */
        CS_SMALLINT     outlen;
        CS_INT          len2;           /* Length of input param */
        CS_SMALLINT     outlen2;

        /*
        ** Get number of input parameters
        */
        srv_numparams(srvproc, &paramnum);

        /*
        ** Only one parameter is expected.
        */
        if (paramnum != 3) {
                /*
                ** Send a usage error message
                */
                xp_message(srvproc, "Invalid number of parameters");
                result = CS_FAIL;
        } else {
                /*
                ** Perform initializations.
                */
                if (sid == 0) {
                        PcaSession*     session=PcaSessionPool::openSession(1);
                        if (!session) {
                                xp_message(srvproc, "openSession failed\n");
                                result = CS_FAIL;
                        }
                        sid=session->openSession(1, "sybasease", "sybasease", "127.0.0.1", "db_user", "os_user", "pgm", 1, "id", "mac");
                }
                outlen = CS_GOODDATA;
                outlen2 = CS_GOODDATA;
                memset(&paramfmt, (CS_INT)0, (CS_INT)sizeof(CS_DATAFMT));
                memset(&paramfmt2, (CS_INT)0, (CS_INT)sizeof(CS_DATAFMT));
                /*
                ** We are receiving data through an ESP as the first parameter.
                ** So describe this expected parameter.
                */
                if ((result == CS_SUCCEED) &&
                        srv_descfmt(srvproc, CS_GET, SRV_RPCDATA, 1, &paramfmt)
                                != CS_SUCCEED) {
                        result = CS_FAIL;
                }

                /*
                ** Describe and bind the buffer to receive the parameter.
                */
                if ((result == CS_SUCCEED) &&
                        (srv_bind(srvproc, CS_GET, SRV_RPCDATA, 1, &paramfmt,
                        (CS_BYTE *) src, &src_len, &outlen) != CS_SUCCEED)) {
                        result = CS_FAIL;
                }
                if ((result == CS_SUCCEED) &&
                        srv_descfmt(srvproc, CS_GET, SRV_RPCDATA, 2, &paramfmt2)
                                != CS_SUCCEED) {
                        result = CS_FAIL;
                }
                /*
                ** Describe and bind the buffer to receive the parameter.
                */
                if ((result == CS_SUCCEED) &&
                        (srv_bind(srvproc, CS_GET, SRV_RPCDATA, 2, &paramfmt2,
                        (CS_BYTE *) enc_col_id, &len2, &outlen2) != CS_SUCCEED)) {
                        result = CS_FAIL;
                }

                /*
                ** Receive the expected data.
                */
                if ((result == CS_SUCCEED) &&
                        srv_xferdata(srvproc,CS_GET,SRV_RPCDATA) != CS_SUCCEED) {
                        result = CS_FAIL;
                }
                /*
                ** Now we have the input info and are ready to send the
                ** output info.
                */
                if (result == CS_SUCCEED) {
                        /*
                        ** Perform initialization.
                        */
                        if (src_len == 0)
                                outlen = CS_NULLDATA;
                        else
                                outlen = CS_GOODDATA;

                        memset(&paramfmt,(CS_INT)0,(CS_INT)sizeof(CS_DATAFMT));
                        strcpy(paramfmt.name, "pls_decrypt_b64_id_proc");
                        paramfmt.namelen = CS_NULLTERM;
                        paramfmt.datatype = CS_CHAR_TYPE;
                        paramfmt.maxlength = BUF_LEN;
                        paramfmt.locale = (CS_LOCALE *) NULL;
                        paramfmt.status |= CS_CANBENULL;
                        paramfmt.status |= CS_RETURN;
                        dgt_sint32 ret=0;
                        CS_INT dst_len = 255;
                        dgt_char  dst[256];
                        memset(dst,0,256);
                        dgt_sint32 col_id=strtol(enc_col_id, NULL, 10);
                        PcaSession*     session=PcaSessionPool::getSession(1);
                        if (!session) {
                                xp_message(srvproc, "getSession failed\n");
                                result = CS_FAIL;
                        }
                        if (session->decrypt(col_id, (dgt_uint8*)src, src_len, (dgt_uint8*)dst, (dgt_uint32*)&dst_len) < 0) {
                                xp_message(srvproc, "encrypt failed\n");
                                result = CS_FAIL;
                        }
                        /*
                        ** Describe the data that is being sent.
                        */
                        if ((result == CS_SUCCEED) &&
                                srv_descfmt(srvproc, CS_SET, SRV_RPCDATA,
                                        1, &paramfmt) != CS_SUCCEED)
                        {
                                result = CS_FAIL;
                        }
                        if ((result == CS_SUCCEED) &&
                                (srv_bind(srvproc, CS_SET, SRV_RPCDATA, 1,
                                &paramfmt, (CS_BYTE *) dst, &dst_len,
                                &outlen) != CS_SUCCEED))
                        {
                                result = CS_FAIL;
                        }

                        /*
                        ** Send the actual data.
                        */
                        if ((result == CS_SUCCEED) &&
                                srv_xferdata(srvproc, CS_SET, SRV_RPCDATA)
                                                != CS_SUCCEED)
                        {
                                result = CS_FAIL;
                        }
                }

                /*
                ** Indicate to the ESP client how the transaction was performed
                */
                if (result == CS_FAIL)
                        srv_sendstatus(srvproc, 1);
                else
                        srv_sendstatus(srvproc, 0);

                /*
                ** Send a count of the number of rows sent to the client.
                */
                srv_senddone(srvproc,(SRV_DONE_COUNT | SRV_DONE_MORE), 0, 1);

        }
        return result;
}
#endif


}
