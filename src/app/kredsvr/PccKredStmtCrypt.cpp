/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtCrypt
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 4. 30
 *   Description        :       KRED crypt statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtCrypt.h"

#include "DgcDbProcess.h"
#include "PccCouponServer.h"
#include "PciKeyMgrIf.h"

PccKredStmtCrypt::PccKredStmtCrypt(DgcPhyDatabase* pdb, DgcSession* session,
                                   DgcSqlTerm* stmt_term)
    : PccKredStmt(pdb, session, stmt_term),
      NumRtnRows(0),
      SrcData(0),
      SrcLen(0),
      DstData(0),
      DstLen(0),
      SqlStmt(0) {
    SelectListDef = new DgcClass("select_list", 1);
    SelectListDef->addAttr(DGC_ACHR, PCI_CRYPT_COL_LEN, "row_data");
}

PccKredStmtCrypt::~PccKredStmtCrypt() {
    if (SrcData) delete SrcData;
    if (DstData) delete DstData;
    delete SqlStmt;
}

dgt_sint32 PccKredStmtCrypt::execute(
    DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcLdbExcept,
                                                    DgcPdbExcept) {
    if (!mrows || !mrows->next()) {
        THROWnR(
            DgcLdbExcept(DGC_EC_LD_STMT_ERR, new DgcError(SPOS, "no bind row")),
            -1);
    }
    defineUserVars(mrows);

    //
    // extract crypt message header
    //
    dgt_uint8* dp = mrows->data();
    dgt_sint32 src_len = 0;
    mcp4((dgt_uint8*)&MsgType, dp);
    mcp8((dgt_uint8*)&EncColID, dp += 4);
    mcp4((dgt_uint8*)&src_len, dp += 8);
    dp += 4;

    //
    // fetch key row
    //
#if 1
    if (SqlStmt == 0) {
        static const dgt_schar* sql_text =
            "select b.*, c.coupon_type, a.data_length from pct_enc_column a, "
            "pct_encrypt_key b,pct_enc_coupon (+) c "
            " where a.enc_col_id=:1 and a.key_id=b.key_id and b.coupon_id = "
            "c.coupon_id";
        if ((SqlStmt = DgcDbProcess::db().getStmt(
                 DgcDbProcess::sess(), sql_text, strlen(sql_text))) == 0) {
            ATHROWnR(DgcError(SPOS, "getStmt[%lld] failed.", EncColID), -1);
        }
    }
    DgcMemRows* br = new DgcMemRows(1);
    br->addAttr(DGC_SB8, 0, "enc_col_id");
    br->add();
    br->rewind();
    br->next();
    *((dgt_sint64*)br->data()) = EncColID;
    br->rewind();
    DgcExcept* e = 0;
    if (SqlStmt->execute(br) < 0) {
        e = EXCEPTnC;
        delete SqlStmt;
        SqlStmt = 0;
        RTHROWnR(e, DgcError(SPOS, "execute[%lld] failed.", EncColID), -1);
    }
    dgt_uint8* key_row;
    if ((key_row = SqlStmt->fetch()) == 0) {
        e = EXCEPTnC;
        delete SqlStmt;
        SqlStmt = 0;
        RTHROWnR(e, DgcError(SPOS, "fetch[%lld] failed", EncColID), -1);
    }
    memcpy(&KeyRow, key_row, sizeof(KeyRow));
#else
    KeyRow.key_id = 1;
    KeyRow.coupon_id = 1;
    KeyRow.coupon_type = 1;
    KeyRow.enc_length = 0;
    KeyRow.key_no = 1;
    KeyRow.key_size = 128;
    KeyRow.cipher_type = 1;
    KeyRow.enc_mode = 2;
    KeyRow.iv_type = 0;
    KeyRow.n2n_flag = 1;
    KeyRow.b64_txt_enc_flag = 1;
    KeyRow.enc_start_pos = 1;
#endif

    //
    // extract source data
    //
    if (src_len > SrcLen) {
        delete SrcData;
        SrcData = new dgt_uint8[SrcLen = src_len];
    }
    dgt_sint32 remains = src_len;
    dgt_sint32 seg_remains = PCI_CRYPT_COL_LEN - 16;
    dgt_uint8* cp = SrcData;
    while (remains > 0) {
        if (seg_remains > remains) seg_remains = remains;
        memcpy(cp, dp, seg_remains);
        if ((remains -= seg_remains) > 0) {
            cp += seg_remains;
            if (mrows->next() && (dp = mrows->data())) {
                seg_remains = PCI_CRYPT_COL_LEN;
            } else {
                THROWnR(
                    DgcLdbExcept(
                        DGC_EC_LD_STMT_ERR,
                        new DgcError(SPOS,
                                     "not enough source data for length[%d:%d]",
                                     src_len, mrows->numRows())),
                    -1);
            }
        }
    }

    //
    // initialize context
    //
    dgt_sint32 rtn = 0;
    if ((rtn = PCI_getEncryptKey(KeyRow.key_no, KeyRow.key_size / 8, Key)) <
        0) {
        THROWnR(
            DgcLdbExcept(
                DGC_EC_LD_STMT_ERR,
                new DgcError(SPOS, "getEncryptKey[%lld] failed due to %d:%s",
                             EncColID, rtn, PCI_getKmgrErrMsg())),
            -1);
    }
    if ((rtn =
             PCI_initContext(&Context, Key, KeyRow.key_size, KeyRow.cipher_type,
                             KeyRow.enc_mode, KeyRow.iv_type, KeyRow.n2n_flag,
                             KeyRow.b64_txt_enc_flag, KeyRow.enc_start_pos,
                             KeyRow.enc_length))) {
        THROWnR(
            DgcLdbExcept(
                DGC_EC_LD_STMT_ERR,
                new DgcError(SPOS, "PCI_initContext[%lld] failed due to %d:%s",
                             EncColID, rtn, PCI_getKmgrErrMsg())),
            -1);
    }

    //
    // crypt
    //
    if (MsgType == PCI_MSG_ENCRYPT) {
        RtnLen = PCI_encryptLength(&Context, src_len);
        if ((RtnLen + 4) > DstLen) {
            if (DstData) delete DstData;
            DstData = new dgt_uint8[DstLen = RtnLen + 4];
        } else
            RtnLen = DstLen;
        if ((rtn = PCI_encrypt(&Context, SrcData, src_len, DstData + 4,
                               &RtnLen))) {
            THROWnR(
                DgcLdbExcept(
                    DGC_EC_LD_STMT_ERR,
                    new DgcError(SPOS, "PCI_encrypt[%lld] failed due to %d:%s",
                                 EncColID, rtn, PCI_getKmgrErrMsg())),
                -1);
        }
    } else if (MsgType == PCI_MSG_DECRYPT) {
        RtnLen = src_len;
        if ((RtnLen + 4) > DstLen) {
            if (DstData) delete DstData;
            DstData = new dgt_uint8[DstLen = RtnLen + 4];
        } else
            RtnLen = DstLen;
        if ((rtn = PCI_decrypt(&Context, SrcData, src_len, DstData + 4,
                               &RtnLen))) {
            THROWnR(
                DgcLdbExcept(
                    DGC_EC_LD_STMT_ERR,
                    new DgcError(SPOS, "PCI_decrypt[%lld] failed due to %d:%s",
                                 EncColID, rtn, PCI_getKmgrErrMsg())),
                -1);
        }
    } else if (MsgType == PCI_MSG_ENCRYPT_COUPON) {
        RtnLen = src_len;
        if ((RtnLen + 4) > DstLen) {
            if (DstData) delete DstData;
            DstData = new dgt_uint8[DstLen = RtnLen + 4];
        } else
            RtnLen = DstLen;
        // issue coupon
        if ((rtn = PetraCouponServer->getCoupon(
                 (const dgt_schar*)SrcData, src_len, KeyRow.coupon_type,
                 &Context, (dgt_schar*)DstData + 4, &RtnLen)) < 0) {
            ATHROWnR(DgcError(SPOS, "get Coupon[%lld] failed.", EncColID), -1);
        }
    } else if (MsgType == PCI_MSG_DECRYPT_COUPON) {
        if (KeyRow.coupon_type == 1 || KeyRow.coupon_type == 3 ||
            KeyRow.coupon_type == 7)
            RtnLen = 48;
        else if (KeyRow.coupon_type == 2 || KeyRow.coupon_type == 4 ||
                 KeyRow.coupon_type == 5 || KeyRow.coupon_type == 6)
            RtnLen = 68;
        else if (KeyRow.coupon_type == 8)
            RtnLen = 194;
        else if (KeyRow.coupon_type == 9)
            RtnLen = 1374;
        if ((RtnLen + 4) > DstLen) {
            if (DstData) delete DstData;
            DstData = new dgt_uint8[DstLen = RtnLen + 4];
        } else
            RtnLen = DstLen;
        if ((rtn = PetraCouponServer->getEncData(
                 (const dgt_schar*)SrcData, src_len, KeyRow.coupon_type,
                 &Context, (dgt_schar*)DstData + 4, &RtnLen)) < 0) {
            ATHROWnR(DgcError(SPOS, "get Dec Data[%lld] failed.", EncColID),
                     -1);
        }
    } else {
        THROWnR(
            DgcLdbExcept(
                DGC_EC_LD_STMT_ERR,
                new DgcError(SPOS, "unknown crypt message type[%d]", MsgType)),
            -1);
    }
    mcp4(DstData, (dgt_uint8*)&RtnLen);
    RtnLen += 4;
    IsExecuted = 1;
    NumRtnRows = 0;
    return 0;
}

dgt_uint8* PccKredStmtCrypt::fetch() throw(DgcLdbExcept, DgcPdbExcept) {
    if (IsExecuted == 0) {
        THROWnR(
            DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                         new DgcError(SPOS, "can't fetch without execution")),
            0);
    }
    if ((NumRtnRows * PCI_CRYPT_COL_LEN) < RtnLen) {
        dgt_uint32 cp_len = DstLen % PCI_CRYPT_COL_LEN;
        if ((DstLen / PCI_CRYPT_COL_LEN) > 0)
            cp_len = PCI_CRYPT_COL_LEN;
        else if (cp_len < (dgt_uint32)PCI_CRYPT_COL_LEN)
            memset(RtnRowData, 0, PCI_CRYPT_COL_LEN);
        memcpy(RtnRowData, (DstData + (NumRtnRows++ * PCI_CRYPT_COL_LEN)),
               cp_len);
        DstLen -= cp_len;
        return RtnRowData;
    }
    THROWnR(DgcLdbExcept(DGC_EC_PD_NOT_FOUND, new DgcError(SPOS, "not found")),
            0);
    return 0;
}
