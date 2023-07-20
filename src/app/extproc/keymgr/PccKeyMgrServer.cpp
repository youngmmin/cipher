/*******************************************************************
 *   File Type          :       external server definition
 *   Classes            :       PccKeyMgrServer
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 26
 *   Description        :       petra cipher key managing external procedure
server
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "DgcDbProcess.h"
#include "DgcDgRepository.h"
#include "DgcProcedureServer.h"
#include "PcaCredentials.h"
#include "PccChangePw.h"
#include "PccCloseKey.h"
#include "PccCreateExtIV.h"
#include "PccCreateExtKey.h"
#include "PccCreateKey.h"
#include "PccCreateRsaKey.h"
#include "PccDropExtIV.h"
#include "PccDropExtKey.h"
#include "PccDropKey.h"
#include "PccExportExtIV.h"
#include "PccExportExtKey.h"
#include "PccExportKey.h"
#include "PccGetCredentials.h"
#include "PccGetKey.h"
#include "PccImportExtIV.h"
#include "PccImportExtKey.h"
#include "PccImportKey.h"
#include "PccOpenKey.h"
#include "PccSetKeyOpenMode.h"
#include "PccTableTypes.h"
#include "PciKeyMgrIf.h"

class PccKeyMgrFactory : public DgcExtProcFactory {
   private:
   protected:
   public:
    PccKeyMgrFactory();
    virtual ~PccKeyMgrFactory();
    virtual dgt_sint32 initialize() throw(DgcExcept);
    virtual dgt_sint32 finalize() throw(DgcExcept);
};

PccKeyMgrFactory::PccKeyMgrFactory()
        : DgcExtProcFactory(/* num_service_handler=2,max_statement=100,max_procedure=1000,max_resource=100 */)
{
}

PccKeyMgrFactory::~PccKeyMgrFactory() {}

dgt_sint32 PccKeyMgrFactory::initialize() throw(DgcExcept) {
    if (DgcDgRepository::p()->load() != 0) {
        ATHROWnR(DgcError(SPOS, "load[Repository] failed"), -1);
    }
    //
    // get the key stash stream which is created by the server's initial method
    //
    DgcStreamSegment* key_stash =
        DgcDbProcess::db().pdb()->segMgr()->getStream("_PCS_KEY_STASH");
    ATHROWnR(DgcError(SPOS, "getStream failed"), -1);
    if (!key_stash) {
        key_stash = DgcDbProcess::db().pdb()->segMgr()->createStream(
            DgcDbProcess::sess(), 1, "_PCS_KEY_STASH");
        ATHROWnR(DgcError(SPOS, "createStream failed"), -1);
        DgcWorker::PLOG.tprintf(0, "create a key stash.\n");
    } else {
        DgcWorker::PLOG.tprintf(0, "get the key stash.\n");
    }
    //
    // set the key stash
    //
    dgt_sint32 rtn = 0;
    if ((rtn = PCI_setKeyStash((PCT_KEY_STASH*)((dgt_uint8*)key_stash +
                                                key_stash->totalSize()))) < 0 &&
        rtn != PCC_ERR_KMGR_KEY_STASH_SET_ALREADY) {
        THROWnR(
            DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                         new DgcError(SPOS, "%d:%s", rtn, PCI_getKmgrErrMsg())),
            -1);
    }
    DgcWorker::PLOG.tprintf(0, "set the key stash.\n");

    //
    // added by chchung, 2012.10.22 for automatic key open
    // automatic key open
    //
    dgt_schar pc_file_path[257];
    memset(pc_file_path, 0, 257);
    dg_sprintf(pc_file_path, "%s/%s/svpw.credentials", getenv("SOHA_HOME"),
               getenv("SOHA_SVC"));
    DgcFileStream pc_fs(pc_file_path, O_RDONLY);
    if (EXCEPT) {
        //
        // no saved password file
        //
        delete EXCEPTnC;
    } else {
        //
        // there's the saved password file
        //
        dgt_sint32 rtn;
        dgt_schar credentials[256];
        memset(credentials, 0, 256);
        if ((rtn = pc_fs.recvData((dgt_uint8*)credentials, 256)) < 0) {
            DgcExcept* e = EXCEPTnC;
            DgcWorker::PLOG.tprintf(0, *e, "read credentials failed due to:\n");
            delete e;
        } else {
            PcaCredentials pc;
            if ((rtn = pc.parse(credentials))) {
                DgcWorker::PLOG.tprintf(
                    0, "parse credentials failed due to:[%d:%s]\n", rtn,
                    pc.errMsg());
            } else if (strcasecmp(pc.svcName(), getenv("SOHA_SVC")) ||
                       strcasecmp(pc.userID(), "SAVED_PW")) {
                DgcWorker::PLOG.tprintf(0, "invalid svc[%s] or user id[%s]\n",
                                        pc.svcName(), pc.userID());
            } else {
                DgcTableSegment* key_tab = (DgcTableSegment*)DgcDbProcess::db()
                                               .pdb()
                                               ->segMgr()
                                               ->getTable("PCT_KEY");
                if (key_tab == 0) {
                    DgcExcept* e = EXCEPTnC;
                    if (e) {
                        DgcWorker::PLOG.tprintf(
                            0, *e, "read credentials failed due to:\n");
                        delete e;
                    } else {
                        DgcWorker::PLOG.tprintf(0, "Table[PCT_KEY] not found");
                    }
                } else {
                    key_tab->unlockShare();
                    DgcRowRef key_rows(key_tab);
                    if (key_rows.next()) {
                        pct_type_key* key_row = (pct_type_key*)key_rows.data();
                        if (key_row->open_mode == 1) {
                            //
                            // added by mwpark
                            // 2017.02.11
                            // for hsm
                            //
                            dgt_sys_param* param;
                            dgt_sint32 hsm_mode = 0;
                            dgt_schar hsm_password[128];
                            memset(hsm_password, 0, 128);
                            if ((param = DG_PARAM("USE_HSM_FLAG")) == 0)
                                delete EXCEPTnC;
                            else {
                                if (param->val_number == 1) {
                                    hsm_mode = 1;
                                    if ((param = DG_PARAM("HSM_PASSWORD")) == 0)
                                        delete EXCEPTnC;
                                    else {
                                        strncpy(hsm_password, param->val_string,
                                                strlen(param->val_string));
                                    }
                                }
                            }
                            if ((rtn = PCI_openKey(
                                     pc.password(), key_row->smk,
                                     strlen(key_row->smk), key_row->seks,
                                     strlen(key_row->seks), key_row->sks,
                                     strlen(key_row->sks), hsm_mode,
                                     hsm_password)) < 0) {
                                DgcWorker::PLOG.tprintf(
                                    0, "open key failed due to [%d:%s]\n", rtn,
                                    PCI_getKmgrErrMsg());
                            } else {
                                dgt_uint32 open_date;
                                open_date = dgtime(&open_date);
                                dgt_schar sql_text[256];
                                memset(sql_text, 0, 256);
                                sprintf(sql_text,
                                        "insert into pct_key_stat "
                                        "values(%lld,%d,%d)",
                                        key_row->key_id, open_date, 1);
                                DgcSession* Session = DgcDbProcess::sess();
                                Session->setDatabaseUser(DGC_SYS_OWNER,
                                                         strlen(DGC_SYS_OWNER));
                                DgcSqlStmt* sql_stmt =
                                    DgcDbProcess::db().getStmt(
                                        Session, sql_text, strlen(sql_text));
                                if (sql_stmt == 0 || sql_stmt->execute() < 0) {
                                    DgcExcept* e = EXCEPTnC;
                                    delete sql_stmt;
                                    RTHROWnR(e,
                                             DgcError(SPOS, "execute failed."),
                                             -1);
                                }
                                DgcWorker::PLOG.tprintf(
                                    0, "the key set opened automatically.\n");
                            }
                        } else {
                            DgcWorker::PLOG.tprintf(
                                0, "no key found for auto-open.\n");
                        }
                    }
                }
            }
        }
    }

    //
    //
    // register all procedures
    //
    if (addProcedure(new PccCreateKey("PCP_CREATE_KEY")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccDropKey("PCP_DROP_KEY")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccOpenKey("PCP_OPEN_KEY")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccCloseKey("PCP_CLOSE_KEY")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccChangePw("PCP_CHANGE_PW")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccExportKey("PCP_EXPORT_KEY")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccImportKey("PCP_IMPORT_KEY")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccSetKeyOpenMode("PCP_SET_KEY_OPEN_MODE")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccGetCredentials("PCP_GET_CREDENTIALS")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccGetKey("PCP_GET_KEY")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccCreateExtKey("PCP_CREATE_EXT_KEY")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccDropExtKey("PCP_DROP_EXT_KEY")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccExportExtKey("PCP_EXPORT_EXT_KEY")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccImportExtKey("PCP_IMPORT_EXT_KEY")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccCreateExtIV("PCP_CREATE_EXT_IV")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccDropExtIV("PCP_DROP_EXT_IV")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccExportExtIV("PCP_EXPORT_EXT_IV")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccImportExtIV("PCP_IMPORT_EXT_IV")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccCreateRsaKey("PCP_CREATE_RSA_KEY")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    return 0;
}

dgt_sint32 PccKeyMgrFactory::finalize() throw(DgcExcept) {
    DgcDgRepository::p()->unload();
    return 0;
}

dgt_void initServerFactory() {
    static PccKeyMgrFactory KeyMgrFactory;       // create a KeyMgrFactory
    DgcProcServer::initFactory(&KeyMgrFactory);  // register the KeyMgrFactory
                                                 // with the Procedure Server
}
