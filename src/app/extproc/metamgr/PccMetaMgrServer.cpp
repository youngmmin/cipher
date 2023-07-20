/*******************************************************************
 *   File Type          :       external server definition
 *   Classes            :       PccMetaMgrServer
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 21
 *   Description        :       petra cipher meta managing external procedure
server
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "DgcDgRepository.h"
#include "DgcProcedureServer.h"
#include "PccAgentTableTest.h"
#include "PccAgentTest.h"
#include "PccChangeScript.h"
#include "PccDropAgent.h"
#include "PccGenScript.h"
#include "PccGenScript2.h"
#include "PccGenScriptAddCol.h"
#include "PccGenScriptColAdmin.h"
#include "PccGenScriptMig.h"
#include "PccGetScript.h"
#include "PccGetTablespace.h"
#include "PccInstAgentPkg.h"
#include "PccInstAgentUser.h"
#include "PccMigValidTest.h"
#include "PccProcSessSqlText.h"
#include "PccProcSessionMonitor.h"
#include "PccRunScript.h"
#include "PccTryDbConn.h"

class PccMetaMgrFactory : public DgcExtProcFactory {
   private:
   protected:
   public:
    PccMetaMgrFactory();
    virtual ~PccMetaMgrFactory();
    virtual dgt_sint32 initialize() throw(DgcExcept);
    virtual dgt_sint32 finalize() throw(DgcExcept);
};

PccMetaMgrFactory::PccMetaMgrFactory()
        : DgcExtProcFactory(/* num_service_handler=2,max_statement=100,max_procedure=1000,max_resource=100 */)
{
}

PccMetaMgrFactory::~PccMetaMgrFactory() {}

dgt_sint32 PccMetaMgrFactory::initialize() throw(DgcExcept) {
    if (DgcDgRepository::p()->load() != 0) {
        ATHROWnR(DgcError(SPOS, "load[Repository] failed"), -1);
    }
    //
    //
    // register all procedures
    //
    if (addProcedure(new PccGetTablespace("PCP_GET_TABLESPACE")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccInstAgentUser("PCP_INST_AGENT_USER")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccInstAgentPkg("PCP_INST_AGENT_PKG")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccDropAgent("PCP_DROP_AGENT")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccAgentTest("PCP_AGENT_TEST")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccAgentTableTest("PCP_AGENT_TABLE_TEST")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccTryDbConn("PCP_TRY_DB_CONN")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccGenScript("PCP_GEN_SCRIPT")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccGetScript("PCP_GET_SCRIPT")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccChangeScript("PCP_CHANGE_SCRIPT")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccRunScript("PCP_RUN_SCRIPT")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccProcSessionMonitor("PCP_SESS_MONITOR")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccProcSessSqlText("PCP_SESS_SQL_TEXT")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccGenScriptAddCol("PCP_GEN_SCRIPT_ADD_COL")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccGenScriptColAdmin("PCP_GEN_SCRIPT_COL_ADMIN")) !=
        0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccGenScriptMig("PCP_GEN_SCRIPT_MIG")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccMigValidTest("PCP_MIG_VALID_TEST")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    if (addProcedure(new PccGenScript2("PCP_GEN_SCRIPT2")) != 0) {
        ATHROWnR(DgcError(SPOS, "addProcedure failed"), -1);
    }
    return 0;
}

dgt_sint32 PccMetaMgrFactory::finalize() throw(DgcExcept) {
    DgcDgRepository::p()->unload();
    return 0;
}

dgt_void initServerFactory() {
    static PccMetaMgrFactory MetaMgrFactory;      // create a MetaMgrFactory
    DgcProcServer::initFactory(&MetaMgrFactory);  // register the MetaMgrFactory
                                                  // with the Procedure Server
}
