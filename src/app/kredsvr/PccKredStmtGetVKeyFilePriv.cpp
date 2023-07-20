/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredStmtGetVKeyFilePriv
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :       KRED get key statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredStmtGetVKeyFilePriv.h"

#include "DgcDbProcess.h"
#include "DgcExprLang.h"

PccKredStmtGetVKeyFilePriv::PccKredStmtGetVKeyFilePriv(DgcPhyDatabase* pdb,
                                                       DgcSession* session,
                                                       DgcSqlTerm* stmt_term)
    : PccKredStmtGetVKeyPriv(pdb, session, stmt_term) {}

PccKredStmtGetVKeyFilePriv::~PccKredStmtGetVKeyFilePriv() {}

dgt_sint32 PccKredStmtGetVKeyFilePriv::execute(
    DgcMemRows* mrows, dgt_sint8 delete_flag) throw(DgcLdbExcept,
                                                    DgcPdbExcept) {
    if (!mrows || !mrows->next()) {
        THROWnR(
            DgcLdbExcept(DGC_EC_LD_STMT_ERR, new DgcError(SPOS, "no bind row")),
            -1);
    }
    defineUserVars(mrows);
    pc_type_get_vkey_file_priv_in* brow =
        (pc_type_get_vkey_file_priv_in*)mrows->data();
    memset(&PrivInfo, 0, sizeof(PrivInfo));

    if (getEncColumn(brow->virtual_key_id, brow->user_sid, brow->crypt_type) <
        0)
        ATHROWnR(DgcError(SPOS, "getEncColumn failed"), -1);

    // PrivInfo.dec_priv = PccDecPrivilege::DEC_ALLOW
    // PrivInfo.dec_priv = PccDecPrivilege::DEC_REJECT_SRC;
    // PrivInfo.dec_priv = PccDecPrivilege::DEC_REJECT_MASKING;
    // PrivInfo.dec_priv = PccDecPrivilege::DEC_REJECT_ERR;

    //
    // get privilege
    //
    dgt_schar* host_name = brow->name1;
    dgt_schar* os_user = brow->name2;
    dgt_schar* file_path = brow->name3;
    dgt_schar* file_name = brow->name4;

    PrivInfo.dec_priv = PccDecPrivilege::DEC_REJECT_ERR;
    if (EncColumn.enc_col_id) {
        //
        // check target list
        //
        DgcTableSegment* cipher_vkey_target_tab =
            PetraTableHandler->getTable("pvat_cipher_vkey_target");
        if (!cipher_vkey_target_tab)
            ATHROWnR(DgcError(SPOS, "getTable[pvat_cipher_vkey_target] failed"),
                     -1);
        DgcIndexSegment* cipher_vkey_target_idx =
            PetraTableHandler->getIndex("pvat_cipher_vkey_target_idx1");
        if (!cipher_vkey_target_idx)
            ATHROWnR(
                DgcError(SPOS, "getIndex[pvat_cipher_vkey_target_idx1] failed"),
                -1);
        pvat_type_cipher_vkey_target target_row;
        memset(&target_row, 0, sizeof(pvat_type_cipher_vkey_target));
        target_row.virtual_key_id = brow->virtual_key_id;
        DgcRowList target_row_list(cipher_vkey_target_tab);
        target_row_list.reset();
        if (cipher_vkey_target_idx->find((dgt_uint8*)&target_row,
                                         target_row_list, 1) < 0) {
            ATHROWnR(DgcError(SPOS, "index search failed"), -1);
        }
        if (target_row_list.numRows() > 0) {
            target_row_list.rewind();
            pvat_type_cipher_vkey_target* vkey_target = 0;
            dgt_sint32 ret = 0;
            while (
                target_row_list.next() &&
                (vkey_target =
                     (pvat_type_cipher_vkey_target*)target_row_list.data())) {
                // check host_name
                if ((ret = matchTargetName(host_name, vkey_target->name1, 1)) <
                    0) {
                    DgcExcept* e = EXCEPTnC;
                    if (e) {
                        DgcWorker::PLOG.tprintf(
                            0, *e, "matchTargetName failed[host_name:%s]\n",
                            host_name);
                        delete e;
                    }
                    continue;
                } else if (ret == 0) {
                    // not matched
                    continue;
                }
                // check os_user
                if ((ret = matchTargetName(os_user, vkey_target->name2, 1)) <
                    0) {
                    DgcExcept* e = EXCEPTnC;
                    if (e) {
                        DgcWorker::PLOG.tprintf(
                            0, *e, "matchTargetName failed[os_user:%s]\n",
                            os_user);
                        delete e;
                    }
                    continue;
                } else if (ret == 0) {
                    // not matched
                    continue;
                }

                // check file_path
                if ((ret = matchTargetName(file_path, vkey_target->name3, 1)) <
                    0) {
                    DgcExcept* e = EXCEPTnC;
                    if (e) {
                        DgcWorker::PLOG.tprintf(
                            0, *e, "matchTargetName failed[file_path:%s]\n",
                            file_path);
                        delete e;
                    }
                    continue;
                } else if (ret == 0) {
                    // not matched
                    continue;
                }

                // check file_name
                if ((ret = matchTargetName(file_name, vkey_target->name4, 1)) <
                    0) {
                    DgcExcept* e = EXCEPTnC;
                    if (e) {
                        DgcWorker::PLOG.tprintf(
                            0, *e, "matchTargetName failed[file_name:%s]\n",
                            file_name);
                        delete e;
                    }
                    continue;
                } else if (ret == 0) {
                    // not matched
                    continue;
                }

                PrivInfo.dec_priv = PccDecPrivilege::DEC_ALLOW;
                break;
            }
        }
    }
    IsExecuted = 1;
    NumRtnRows = 0;

    return 0;
}
