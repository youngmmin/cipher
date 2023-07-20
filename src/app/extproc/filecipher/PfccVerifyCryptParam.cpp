/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PfccVerifyCryptParam
 *   Implementor        :       mjkim
 *   Create Date        :       2019. 01. 09
 *   Description        :       verify crypt parameter
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PfccVerifyCryptParam.h"

#include <regex.h>

#include "DgcBgmrList.h"
#include "DgcBgrammer.h"
#include "DgcSqlHandle.h"

PfccVerifyCryptParam::PfccVerifyCryptParam(const dgt_schar* name)
    : DgcExtProcedure(name) {}

PfccVerifyCryptParam::~PfccVerifyCryptParam() {}

DgcExtProcedure* PfccVerifyCryptParam::clone() {
    return new PfccVerifyCryptParam(procName());
}

dgt_sint32 PfccVerifyCryptParam::checkKeyExists(
    const dgt_schar* key_name) throw(DgcExcept) {
    dgt_schar key_tab[19] = {0};
    dgt_schar key_col[19] = {0};

    DgcSqlHandle sql_handle(DgcDbProcess::sess());
    dgt_schar sql_text[256] = {0};

    // seperate key name
    for (dgt_uint32 i = 0; i < strlen(key_name); i++) {
        if (key_name[i] == '.') {
            strncpy(key_tab, key_name, i++);
            strncpy(key_col, key_name + i, strlen(key_name) - i);
            break;
        }
    }
    // check pct_enc_table : table_name
    dgt_uint8* ret = 0;
    sprintf(sql_text,
            "select ENC_TAB_ID from PCT_ENC_TABLE where TABLE_NAME like '%s'",
            key_tab);
    if (sql_handle.execute(sql_text) < 0)
        ATHROWnR(DgcError(SPOS, "execute failed"), -1);
    if (!(ret = sql_handle.fetch())) return -1;
    dgt_sint64 enc_tab_id = *(dgt_sint64*)ret;

    // check pct_enc_column : column_name +  enc_table_id
    sprintf(sql_text,
            "select ENC_COL_ID from PCT_ENC_COLUMN where ENC_TAB_ID = %lld and "
            "COLUMN_NAME like '%s'",
            enc_tab_id, key_col);
    if (sql_handle.execute(sql_text) < 0)
        ATHROWnR(DgcError(SPOS, "execute failed"), -1);
    if (!sql_handle.fetch()) return -1;

    return 0;
}

dgt_sint32 PfccVerifyCryptParam::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    pfcc_verify_crypt_param_in* param_in =
        (pfcc_verify_crypt_param_in*)BindRows->data();
    if (!param_in)
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "no input row")),
                -1);

    ReturnRows->reset();
    ReturnRows->add();
    ReturnRows->next();
    pfcc_verify_crypt_param_out param_out;

    // verify crypt_param format ()
    dgt_sint32 idx = 0;
    while (param_in->crypt_param[idx] != '(') {
        if (param_in->crypt_param[idx] == ' ') {
            idx++;
        } else {
            param_out.rtn_code = PFC_VRFY_ERR_INVALID_PARAM_FORMAT;
            sprintf(param_out.err_msg, "invalid param format [%s]",
                    param_in->crypt_param);
            memcpy(ReturnRows->data(), &param_out,
                   sizeof(pfcc_verify_crypt_param_out));
            ReturnRows->rewind();
            return 0;
        }
    }
    DgcBgmrList* ParamList = new DgcBgmrList(param_in->crypt_param, 1);
    if (EXCEPT) {
        DgcExcept* e = EXCEPTnC;
        if (e) {
            param_out.rtn_code = PFC_VRFY_ERR_INVALID_PARAM_FORMAT;
            sprintf(param_out.err_msg, "invalid param format [%s]",
                    param_in->crypt_param);
            memcpy(ReturnRows->data(), &param_out,
                   sizeof(pfcc_verify_crypt_param_out));
            delete e;
            delete ParamList;
            ReturnRows->rewind();
            return 0;
        }
    }

    // verify crypt_paramp parameters
    DgcBgrammer* bg = 0;
    while ((bg = ParamList->getNext())) {
        if (bg->getNode("key")) {
            for (dgt_sint32 col_no = 1;; col_no++) {
                dgt_schar* enc_name;
                dgt_schar* col_string;
                dgt_schar node_name[128];
                sprintf(node_name, "key.%d.name", col_no);
                if ((enc_name = bg->getValue(node_name))) {
                    sprintf(node_name, "key.%d.columns", col_no);
                    if (!(col_string = bg->getValue(node_name))) {
                        param_out.rtn_code = PFC_VRFY_ERR_KEY_COL_NOT_DEFINED;
                        sprintf(param_out.err_msg,
                                "not define columns in key node [col_no:%d]",
                                col_no);
                        memcpy(ReturnRows->data(), &param_out,
                               sizeof(pfcc_verify_crypt_param_out));
                        ReturnRows->rewind();
                        return 0;
                    }
                    if (checkKeyExists(enc_name)) {  // check if key exists
                        param_out.rtn_code = PFC_VRFY_ERR_KEY_COL_NOT_FOUND;
                        sprintf(
                            param_out.err_msg,
                            "not found key node[col_no:%d]'s key[%s] on server",
                            col_no, enc_name);
                        memcpy(ReturnRows->data(), &param_out,
                               sizeof(pfcc_verify_crypt_param_out));
                        ReturnRows->rewind();
                        return 0;
                    }
                } else {  // not define key name
                    if (col_no == 1) {
                        param_out.rtn_code = PFC_VRFY_ERR_KEY_NAME_NOT_DEFINED;
                        sprintf(param_out.err_msg,
                                "not define name in key node [col_no:%d]",
                                col_no);
                        memcpy(ReturnRows->data(), &param_out,
                               sizeof(pfcc_verify_crypt_param_out));
                        ReturnRows->rewind();
                        return 0;
                    }
                    break;
                }
            }
        } else if (bg->getNode("mode")) {
            if (bg->getValue("mode.crypt")) {
                param_out.rtn_code = PFC_VRFY_ERR_MODE_CRYPT_NOT_SUPPORTED;
                sprintf(param_out.err_msg,
                        "unsupported parameter \"mode.crypt\"");
                memcpy(ReturnRows->data(), &param_out,
                       sizeof(pfcc_verify_crypt_param_out));
                ReturnRows->rewind();
                return 0;
            }
        } else if (bg->getNode("regular")) {
            dgt_sint32 rtn = 0;
            dgt_schar expr_string[32];
            dgt_schar* val = 0;
            dgt_sint32 col_no;
            for (col_no = 1;; col_no++) {
                dgt_sint32 expr_no;
                for (expr_no = 1;; expr_no++) {
                    sprintf(expr_string, "regular.%d.%d", col_no, expr_no);
                    if ((val =
                             bg->getValue(expr_string))) {  // check expr_string
                        regex_t regex;
                        dgt_sint32 ret = 0;
                        dgt_schar err_msg[100] = {0};
                        if ((ret = regcomp(&regex, val, REG_EXTENDED))) {
                            regerror(ret, &regex, err_msg, 100);
                            param_out.rtn_code =
                                PFC_VRFY_ERR_REGUALR_REGEX_ERROR;
                            sprintf(param_out.err_msg, "%s", err_msg);
                            memcpy(ReturnRows->data(), &param_out,
                                   sizeof(pfcc_verify_crypt_param_out));
                            ReturnRows->rewind();
                            return 0;
                        }
                    } else
                        break;
                }
                if (expr_no == 1) break;
            }
            if (col_no == 1) {  // no expression
                param_out.rtn_code = PFC_VRFY_ERR_REGULAR_NOT_DEFINED;
                sprintf(param_out.err_msg, "not define regular expression");
                memcpy(ReturnRows->data(), &param_out,
                       sizeof(pfcc_verify_crypt_param_out));
                ReturnRows->rewind();
                return 0;
            }
        }
    }

    // return success
    param_out.rtn_code = 0;
    sprintf(param_out.err_msg, "success");
    memcpy(ReturnRows->data(), &param_out, sizeof(pfcc_verify_crypt_param_out));
    ReturnRows->rewind();
    return 0;
}
