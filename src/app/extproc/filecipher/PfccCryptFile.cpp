/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PfccCryptFile
 *   Implementor        :       jhpark
 *   Create Date        :       2018. 01. 11
 *   Description        :       get EncTgtSys table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PfccCryptFile.h"

#include "DgcDgConstType.h"
#include "DgcSqlHandle.h"
#include "PfccAgentProcSvr.h"

PfccCryptFile::PfccCryptFile(const dgt_schar* name,
                             PfccAgentListener* agent_listener)
    : PfccAgentProcedure(name, agent_listener) {}

PfccCryptFile::~PfccCryptFile() {}

DgcExtProcedure* PfccCryptFile::clone() {
    return new PfccCryptFile(procName(), AgentListener);
}

dgt_sint32 PfccCryptFile::initialize() throw(DgcExcept) { return 0; }

dgt_sint32 PfccCryptFile::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    pfct_crypt_file_in* param_in = (pfct_crypt_file_in*)BindRows->data();

    pr_debug("agent_id[%lld]\n", param_in->agent_id);
    pr_debug("ptu_id[%lld]\n", param_in->ptu_id);
    pr_debug("enc_zone_id[%lld]\n", param_in->enc_zone_id);
    pr_debug("crypt_flag[%lld]\n", param_in->crypt_flag);
    pr_debug("client_ip[%s]\n", param_in->client_id);
    pr_debug("in_file_name[%s]\n", param_in->src_file);
    pr_debug("out_file_name[%s]\n", param_in->dst_file);

    // 2. build bind values
    DgcMemRows bind_vars(6);
    bind_vars.addAttr(DGC_SB8, 0, "ptu_id");
    bind_vars.addAttr(DGC_SB8, 0, "enc_zone_id");
    bind_vars.addAttr(DGC_UB1, 0, "crypt_flag");
    bind_vars.addAttr(DGC_SCHR, 128, "client_ip");
    bind_vars.addAttr(DGC_SCHR, 2049, "in_file_name");
    bind_vars.addAttr(DGC_SCHR, 2049, "out_file_name");
    bind_vars.reset();

    pcct_crypt_file_in* file_in = 0;
    bind_vars.add();
    bind_vars.next();
    file_in = (pcct_crypt_file_in*)bind_vars.data();
    file_in->ptu_id = param_in->ptu_id;
    file_in->enc_zone_id = param_in->enc_zone_id;
    file_in->crypt_flag = param_in->crypt_flag;
    strcpy(file_in->client_ip, param_in->client_ip);
    strcpy(file_in->in_file_name, param_in->src_file);
    strcpy(file_in->out_file_name, param_in->dst_file);

    // 3. execute stmt
    if (AgentSession)
        AgentListener->agentSessPool().returnSession(AgentSession);
    AgentSession =
        AgentListener->agentSessPool().getSession(param_in->agent_id);
    if (AgentSession == 0) {
        THROWnR(DgcDgExcept(
                    DGC_EC_DG_INVALID_STAT,
                    new DgcError(SPOS, "agent[%lld] has no available session\n",
                                 param_in->agent_id)),
                -1);
    }

    dgt_schar sql_text[256] = {
        0,
    };
    sprintf(sql_text, "cryptFile");
    DgcCliStmt* cli_stmt = AgentSession->getStmt();
    ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);
    if (cli_stmt->open(sql_text, strlen(sql_text))) {
        AgentSession->setBrokenFlag();
        DgcExcept* e = EXCEPTnC;
        delete cli_stmt;
        RTHROWnR(e, DgcError(SPOS, "open failed"), -1);
    }

    bind_vars.rewind();
    if (cli_stmt->execute(10, &bind_vars) < 0) {
        AgentSession->setBrokenFlag();
        DgcExcept* e = EXCEPTnC;
        delete cli_stmt;
        RTHROWnR(e, DgcError(SPOS, "execute failed"), -1);
    }

    // 4. get return code
    dgt_sint32 frows = cli_stmt->fetch();
    if (frows < 0) {
        AgentSession->setBrokenFlag();
        DgcExcept* e = EXCEPTnC;
        delete cli_stmt;
        RTHROWnR(e, DgcError(SPOS, "fetch failed"), -1);
    } else {
        ReturnRows->reset();
        DgcMemRows* rtn_rows = cli_stmt->returnRows();
        if (rtn_rows) {
            rtn_rows->rewind();
            if (rtn_rows->next()) {
                pcct_crypt_file_out* file_out =
                    (pcct_crypt_file_out*)rtn_rows->data();
                pr_debug("error_message[%s] \n", file_out->error_message);
                ReturnRows->add();
                ReturnRows->next();
                // pr_debug("%*.*s %lld %lld %lld %lld %u %u
                // %u\n",32,32,de->name,de->file_id,de->dir_id,de->zone_id,de->file_size,de->last_update,de->type,de->encrypt_flag);
                pfct_crypt_file_out* result_out = 0;
                result_out = (pfct_crypt_file_out*)ReturnRows->data();
                if (result_out) {
                    result_out->rtn_code = file_out->rtn_code;
                    if (result_out->rtn_code) {
                        dgt_sint32 err_msg_len =
                            dg_strlen(file_out->error_message);
                        strncpy(result_out->err_msg, file_out->error_message,
                                err_msg_len > 1024 ? 1024 : err_msg_len);
                    } else {
                        strcpy(result_out->err_msg, "success");
                    }
                }
            }
        }
    }

    delete cli_stmt;

    ReturnRows->rewind();
    return 0;
}
