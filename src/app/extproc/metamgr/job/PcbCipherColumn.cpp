/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PcbCipherColumn
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcbCipherColumn.h"

PcbCipherColumn::PcbCipherColumn(dgt_sint64 enc_col_id)
    : EncColumnID(enc_col_id) {
    IdxColumnOrder = 0;
    dg_memset(Key, 0, 64);
    DomainIndexFlag = 0;
}

PcbCipherColumn::~PcbCipherColumn() {}

#include "DgcDbProcess.h"
#include "PciKeyMgrIf.h"

dgt_sint32 PcbCipherColumn::initialize() throw(DgcExcept) {
    dgt_schar sql_txt[256] = {
        0,
    };

    //
    // get encrypt column info
    //
    sprintf(sql_txt, "select * from pct_enc_column where enc_col_id=%lld",
            EncColumnID);
    DgcSqlStmt* sql_stmt = DgcDbProcess::db().getStmt(DgcDbProcess::sess(),
                                                      sql_txt, strlen(sql_txt));
    if (!sql_stmt) {
        ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);
    }
    if (sql_stmt->execute() >= 0) {
        dgt_uint8* rowd;
        if ((rowd = sql_stmt->fetch())) {
            memcpy(&EncColumn, rowd, sizeof(EncColumn));
        }
    }
    DgcExcept* e = EXCEPTnC;
    delete sql_stmt;
    sql_stmt = 0;
    if (e) RTHROWnR(e, DgcError(SPOS, "execute/fetch failed"), -1);

    //
    // get encrypt column`s index(domain index)
    //
    sprintf(sql_txt,
            "select count() from pct_enc_index where enc_col_id=%lld and "
            "index_type =1",
            EncColumnID);
    sql_stmt = DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_txt,
                                          strlen(sql_txt));
    if (!sql_stmt) {
        ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);
    }
    if (sql_stmt->execute() >= 0) {
        dgt_uint8* rowd;
        dgt_sint64 count;
        if ((rowd = sql_stmt->fetch())) {
            memcpy(&count, rowd, sizeof(dgt_sint64));
            if (count > 0) DomainIndexFlag = 1;
        }
    }
    e = EXCEPTnC;
    delete sql_stmt;
    sql_stmt = 0;
    if (e) RTHROWnR(e, DgcError(SPOS, "execute/fetch failed"), -1);

    //
    // get encrypt schema info
    //
    sprintf(sql_txt,
            "select b.* from pct_enc_column a, pct_encrypt_key b where "
            "a.key_id=b.key_id and a.enc_col_id=%lld",
            EncColumnID);
    sql_stmt = DgcDbProcess::db().getStmt(DgcDbProcess::sess(), sql_txt,
                                          strlen(sql_txt));
    if (!sql_stmt) {
        ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);
    }
    if (sql_stmt->execute() >= 0) {
        dgt_uint8* rowd;
        if ((rowd = sql_stmt->fetch())) {
            memcpy(&EncKey, rowd, sizeof(EncKey));
        }
    }
    e = EXCEPTnC;
    delete sql_stmt;
    sql_stmt = 0;
    if (e)
        RTHROWnR(e,
                 DgcError(SPOS, "PCT_ENCRYPT_KEY[%lld] execute/fetch failed",
                          EncColumnID),
                 -1);

    //
    // get the encryption key
    //
    dgt_sint32 rtn = 0;
    if ((rtn = PCI_getEncryptKey(EncKey.key_no, EncKey.key_size / 8, Key)) <
        0) {
        THROWnR(
            DgcLdbExcept(
                DGC_EC_LD_STMT_ERR,
                new DgcError(SPOS, "getEncryptKey[%lld] failed due to %d:%s",
                             EncColumnID, rtn, PCI_getKmgrErrMsg())),
            -1);
    }
    if ((rtn = PCI_initContext(&CipherContext, Key, EncKey.key_size,
                               EncKey.cipher_type, EncKey.enc_mode,
                               EncKey.iv_type, EncKey.n2n_flag,
                               EncKey.b64_txt_enc_flag, EncKey.enc_start_pos,
                               EncKey.enc_length, DomainIndexFlag)) < 0) {
        THROWnR(
            DgcLdbExcept(
                DGC_EC_LD_STMT_ERR,
                new DgcError(SPOS, "PCI_initContext[%lld] failed due to %d:%s",
                             EncColumnID, rtn, PCI_getErrMsg(&CipherContext))),
            -1);
    }

    return 0;
}

dgt_sint32 PcbCipherColumn::initializeIndexColumns(
    const pct_type_enc_column* enc_column, const pct_type_encrypt_key* enc_key,
    const PCI_Context* cipher_context) throw(DgcExcept) {
    dg_memcpy(&EncColumn, enc_column, sizeof(EncColumn));
    dg_memcpy(&EncKey, enc_key, sizeof(EncKey));
    dg_memcpy(&CipherContext, cipher_context, sizeof(CipherContext));

    // EncColumn.data_length=2000;
    // dg_memset(EncColumn.data_type,0,sizeof(EncColumn.data_type));
    // dg_strcpy(EncColumn.data_type,"RAW");
    //
    // get the encryption key
    //
#if 0
	dgt_sint32      rtn=0;
        if ((rtn=PCI_getEncryptKey(EncKey.key_no, EncKey.key_size/8, Key)) < 0) {
                THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                        new DgcError(SPOS,"getEncryptKey[%lld] failed due to %d:%s",EncColumnID, rtn, PCI_getKmgrErrMsg())),-1);
        }
	if ((rtn=PCI_initContext(&CipherContext, Key, EncKey.key_size,
				EncKey.cipher_type, EncKey.enc_mode,
				EncKey.iv_type, EncKey.n2n_flag,
				EncKey.b64_txt_enc_flag, EncKey.enc_start_pos)) < 0) {
                THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                        new DgcError(SPOS,"PCI_initContext[%lld] failed due to %d:%s",EncColumnID, rtn, PCI_getErrMsg(&CipherContext))),-1);
	}
#endif
    return 0;
}

dgt_uint8 PcbCipherColumn::colType() {
    if (!strcasecmp(EncColumn.data_type, "VARCHAR") ||
        !strcasecmp(EncColumn.data_type, "VARCHAR2") ||
        !strcasecmp(EncColumn.data_type, "STRING") ||
        !strcasecmp(EncColumn.data_type, "CHAR"))
        return PCB_COL_TYPE_CHR;
    else if (!strcasecmp(EncColumn.data_type, "NUMBER") ||
             !strcasecmp(EncColumn.data_type, "LONG") ||
             !strcasecmp(EncColumn.data_type, "SHORT"))
        return PCB_COL_TYPE_NUM;
    else if (!strcasecmp(EncColumn.data_type, "DATE"))
        return PCB_COL_TYPE_DATE;
    else if (!strcasecmp(EncColumn.data_type, "RAW"))
        return PCB_COL_TYPE_BIN;
    return PCB_COL_TYPE_2CHR;
}

dgt_uint32 PcbCipherColumn::encryptLength(dgt_sint32 src_len) {
    dgt_sint32 out_enc_len;
    return PCI_encryptLength(&CipherContext, src_len, &out_enc_len);
}

dgt_sint32 PcbCipherColumn::encrypt(PcbDataColumn* data_column) throw(
    DgcExcept) {
    dgt_sint32 rtn;
    dgt_sint32 src_len;
    dgt_uint32 dst_len;
    for (dgt_uint32 rno = 0; rno < data_column->numRows(); rno++) {
        src_len = *data_column->colLen(rno);
        if (*data_column->colInd(rno)) src_len = 0;  // null
        dst_len = data_column->maxEncColLen();
        if (DomainIndexFlag == 1) {
            dgt_uint32 ophDstLen = src_len + 1;
            if ((rtn = PCI_OPHUEK(
                     &CipherContext, (dgt_uint8*)data_column->colData(rno),
                     src_len, (dgt_uint8*)data_column->encColData(rno),
                     &ophDstLen, EncColumnID, PCI_SRC_TYPE_CHAR, 0, 1)) < 0) {
                THROWnR(
                    DgcLdbExcept(
                        DGC_EC_LD_STMT_ERR,
                        new DgcError(
                            SPOS, "PCI_OPHUEK[%lld] failed due to %d:%s",
                            EncColumnID, rtn, PCI_getErrMsg(&CipherContext))),
                    -1);
            }
            dgt_uint32 encDstLen = dst_len;
            if ((rtn = PCI_encrypt(
                     &CipherContext, (dgt_uint8*)data_column->colData(rno),
                     src_len,
                     (dgt_uint8*)data_column->encColData(rno) + ophDstLen,
                     &encDstLen, (dgt_uint8)ophDstLen)) < 0) {
                THROWnR(
                    DgcLdbExcept(
                        DGC_EC_LD_STMT_ERR,
                        new DgcError(
                            SPOS, "PCI_encrypt[%lld] failed due to %d:%s",
                            EncColumnID, rtn, PCI_getErrMsg(&CipherContext))),
                    -1);
            }
            *(data_column->encColLen(rno)) = (dgt_uint16)ophDstLen + encDstLen;
        } else {
            if ((rtn = PCI_encrypt(
                     &CipherContext, (dgt_uint8*)data_column->colData(rno),
                     src_len, (dgt_uint8*)data_column->encColData(rno),
                     &dst_len)) < 0) {
                THROWnR(
                    DgcLdbExcept(
                        DGC_EC_LD_STMT_ERR,
                        new DgcError(
                            SPOS, "PCI_encrypt[%lld] failed due to %d:%s",
                            EncColumnID, rtn, PCI_getErrMsg(&CipherContext))),
                    -1);
            }
            *(data_column->encColLen(rno)) = (dgt_uint16)dst_len;
        }
    }
    return 0;
}

#include "DgcBase64.h"

dgt_sint32 PcbCipherColumn::decrypt(PcbDataColumn* data_column,
                                    dgt_uint8 verify_flag) throw(DgcExcept) {
    dgt_sint32 rtn;
    dgt_sint32 src_len;
    dgt_uint32 dst_len;
    dgt_uint8* tmp_buf = new dgt_uint8[data_column->maxEncColLen()];
    for (dgt_uint32 rno = 0; rno < data_column->numRows(); rno++) {
        src_len = *data_column->encColLen(rno);
        dst_len = data_column->maxEncColLen();
        if (DomainIndexFlag == 1 && src_len) {
            dgt_sint32 ophLen = 0;
            dgt_uint8* b64_tailer = (dgt_uint8*)data_column->encColData(rno) +
                                    src_len - 4;  // 4 = PCC_ENC_TRAILER_LENGTH;
            dgt_uint8 trailer[3] = {0, 0, 0};
            DgcBase64::decode((dgt_schar*)b64_tailer, 4, trailer, 3);
            if (trailer[2]) {
                ophLen = trailer[2];
                if ((rtn = PCI_decrypt(
                         &CipherContext,
                         (dgt_uint8*)data_column->encColData(rno) + ophLen,
                         src_len - ophLen, tmp_buf, &dst_len)) < 0) {
                    if (verify_flag) {
                        //
                        // although PCI_decrypt failed, process must be go on
                        // while a verification.
                        //
                        if (EXCEPTnC) delete EXCEPTnC;
                        const dgt_schar* err_data = "verification failed.";
                        dst_len = dg_strlen(err_data);
                        memcpy(tmp_buf, err_data, dst_len);
                    } else {
                        delete tmp_buf;
                        THROWnR(DgcLdbExcept(
                                    DGC_EC_LD_STMT_ERR,
                                    new DgcError(
                                        SPOS,
                                        "PCI_decrypt[%lld] failed due to %d:%s",
                                        EncColumnID, rtn,
                                        PCI_getErrMsg(&CipherContext))),
                                -1);
                    }
                }
            } else {
                if ((rtn = PCI_decrypt(&CipherContext,
                                       (dgt_uint8*)data_column->encColData(rno),
                                       src_len, tmp_buf, &dst_len)) < 0) {
                    if (verify_flag) {
                        //
                        // although PCI_decrypt failed, process must be go on
                        // while a verification.
                        //
                        if (EXCEPTnC) delete EXCEPTnC;
                        const dgt_schar* err_data = "verification failed.";
                        dst_len = dg_strlen(err_data);
                        memcpy(tmp_buf, err_data, dst_len);
                    } else {
                        delete tmp_buf;
                        THROWnR(DgcLdbExcept(
                                    DGC_EC_LD_STMT_ERR,
                                    new DgcError(
                                        SPOS,
                                        "PCI_decrypt[%lld] failed due to %d:%s",
                                        EncColumnID, rtn,
                                        PCI_getErrMsg(&CipherContext))),
                                -1);
                    }
                }
            }
        } else {
            if ((rtn = PCI_decrypt(&CipherContext,
                                   (dgt_uint8*)data_column->encColData(rno),
                                   src_len, tmp_buf, &dst_len)) < 0) {
                if (verify_flag) {
                    //
                    // although PCI_decrypt failed, process must be go on while
                    // a verification.
                    //
                    if (EXCEPTnC) delete EXCEPTnC;
                    const dgt_schar* err_data = "verification failed.";
                    dst_len = dg_strlen(err_data);
                    memcpy(tmp_buf, err_data, dst_len);
                } else {
                    delete tmp_buf;
                    THROWnR(
                        DgcLdbExcept(
                            DGC_EC_LD_STMT_ERR,
                            new DgcError(
                                SPOS, "PCI_decrypt[%lld] failed due to %d:%s",
                                EncColumnID, rtn,
                                PCI_getErrMsg(&CipherContext))),
                        -1);
                }
            }
        }
        if (dst_len > data_column->maxColLen())
            *(data_column->colLen(rno)) = data_column->maxColLen();
        else
            *(data_column->colLen(rno)) = (dgt_uint16)dst_len;
        memcpy(data_column->colData(rno), tmp_buf, *(data_column->colLen(rno)));
        if (dst_len)
            *data_column->colInd(rno) = 0;
        else
            *data_column->colInd(rno) = 1;
    }
    delete tmp_buf;
    return 0;
}

dgt_uint32 PcbCipherColumn::ophuekLength(dgt_sint32 src_length,
                                         dgt_uint8 src_type) {
    dgt_sint32 src_len = 0;

    // max column length
    if (src_type == PCI_SRC_TYPE_NUM)
        src_len = 22;
    else if (src_type == PCI_SRC_TYPE_DATE)
        src_len = 7;
    else
        src_len = src_length;

    if (EncColumn.multi_byte_flag) src_len *= 3;
    return PCI_ophuekLength(src_len, src_type, 0);
}

dgt_sint32 PcbCipherColumn::ophuek(
    PcbDataColumn* index_data_column,
    PcbDataColumn* data_column) throw(DgcExcept) {
    dgt_sint32 rtn;
    dgt_sint32 src_len;
    dgt_uint32 dst_len;
    dgt_uint8 col_type = colType();
    dst_len = ophuekLength(EncColumn.data_length, col_type);
    // dst_len=PCI_ophuekLength(EncColumn.data_length>1?EncColumn.data_length:EncColumn.data_precision,col_type);
    for (dgt_uint32 rno = 0; rno < data_column->numRows(); rno++) {
        src_len = *data_column->colLen(rno);
        if (*data_column->colInd(rno)) src_len = 0;  // null
#if 0
if(rno==0){
	printf("############ OPHUEK ###########\n");
	printf("EncColID[%d]\n",EncColumnID);
	printf("dst_len[%d] \n",dst_len);
	printf("MaxColLen[%d]\n",data_column->maxColLen());
	printf("ColType[%d] \n",col_type);
	printf("MultiByteflag[%d]\n",EncColumn.multi_byte_flag);
	printf("######### CipherContext ########\n");
	printf("enc_length[%d], key_size[%d], cipher_type[%d], enc_mode[%d], iv_type[%d], n2n_flag[%d], b64_txt_enc_flag[%d], enc_start_pos[%d], remains[%d], double_enc_check[%d], iv_index[%d], block_size[%d], err_code[%d]\n",
			CipherContext.enc_length, CipherContext.key_size,
			CipherContext.cipher_type, CipherContext.enc_mode,
			CipherContext.iv_type, CipherContext.n2n_flag,
			CipherContext.b64_txt_enc_flag, CipherContext.enc_start_pos,
			CipherContext.remains, CipherContext.double_enc_check,
			CipherContext.iv_index, CipherContext.block_size,
			CipherContext.err_code);
	printf("################################\n");
}
#endif

        if ((rtn = PCI_OPHUEK(&CipherContext,
                              (dgt_uint8*)data_column->colData(rno), src_len,
                              (dgt_uint8*)index_data_column->encColData(rno),
                              &dst_len, EncColumnID, col_type, 0, 0)) < 0) {
            THROWnR(DgcLdbExcept(
                        DGC_EC_LD_STMT_ERR,
                        new DgcError(
                            SPOS, "PCI_OPHUEK[%lld] failed due to %d:%s",
                            EncColumnID, rtn, PCI_getErrMsg(&CipherContext))),
                    -1);
        }

        *(index_data_column->encColLen(rno)) = (dgt_uint16)dst_len;
#if 0
if(rno==0){
	printf("############ INDEX DATA ###########\n");
	printf("EncColID[%d]\n",EncColumnID);
	printf("maxColLen[%d]\n",index_data_column->maxColLen());
	printf("maxEncColLen[%d]\n",index_data_column->maxEncColLen());
	printf("colLen[%d]\n",*index_data_column->colLen(rno));
	printf("encColLen[%d]\n",*index_data_column->encColLen(rno));
	printf("encColData[");
	for(dgt_uint32 i=0; i<dst_len;i++) printf("%02x",*((dgt_uint8*)index_data_column->encColData(rno)+i));
	printf("][%d]\n",dst_len);
	printf("################################\n");
}
#endif
    }

    // printf("PcbCipherColumn::ophuek  END\n");
    return 0;
}
