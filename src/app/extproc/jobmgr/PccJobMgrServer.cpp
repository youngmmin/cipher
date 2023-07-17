/*******************************************************************
 *   File Type          :       external server definition
 *   Classes            :       PccJobMgrServer
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 21
 *   Description        :       petra cipher meta managing external procedure server
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "DgcDgRepository.h"
#include "DgcProcedureServer.h"
#include "PetraCipherScheduler.h"
#include "PccEncrypt.h"
#include "PccDecrypt.h"
#include "PccRunJob.h"
#include "PccRunMigJob.h"
#include "PccRunVerify.h"
#include "PccRunMigVerify.h"
#include "PccStopJob.h"
#include "PccRunSchedule.h"
#include "PccRunMigSchedule.h"
#include "PccRunVerifySchedule.h"
#include "PccRunMigVerifySchedule.h"
#include "PccJobProgress.h"


class PccJobMgrFactory : public DgcExtProcFactory {
  private:
	PetraCipherScheduler*	Scheduler;	
  protected:
  public:
        PccJobMgrFactory();
        virtual ~PccJobMgrFactory();
	virtual dgt_sint32 initialize() throw(DgcExcept);
	virtual dgt_sint32 finalize() throw(DgcExcept);
};


PccJobMgrFactory::PccJobMgrFactory()
        : DgcExtProcFactory(/* num_service_handler=2,max_statement=100,max_procedure=1000,max_resource=100 */),
	  Scheduler(0)
{
}


PccJobMgrFactory::~PccJobMgrFactory()
{
}


dgt_sint32 PccJobMgrFactory::initialize() throw(DgcExcept)
{
	//
	// load repository
	//
	if (DgcDgRepository::p()->load() != 0) {
		ATHROWnR(DgcError(SPOS,"load[Repository] failed"),-1);
	}

	//
	// start scheduler
	//
        dgt_worker*     wa;

	if ((wa=DgcDbProcess::db().getWorker(DgcDbProcess::sess())) == 0) {
		DgcExcept*	e=EXCEPTnC;
		DgcWorker::PLOG.tprintf(0,*e,"getWorker for scheduler failed due to the below:\n");
		delete e;
	} else {
        	dg_strncpy(wa->Owner,DGC_SYS_OWNER,strlen(DGC_SYS_OWNER));
		wa->PID=DgcDbProcess::pa().pid;
                wa->LWID=wa->WID;

		Scheduler=new PetraCipherScheduler(wa);
		if (Scheduler->initialize()) {
			DgcExcept*	e=EXCEPTnC;
			DgcWorker::PLOG.tprintf(0,*e,"initialize failed due to the below:\n");
			delete e;
			delete Scheduler;
			Scheduler=0;
		} else if (Scheduler->start() != 0) {
			DgcExcept*	e=EXCEPTnC;
			DgcWorker::PLOG.tprintf(0,*e,"start scheduler failed due to the below exception:");
			if (e->classid() == DGC_EXT_WORKER) {
				delete Scheduler;
				Scheduler=0;
			}
			delete e;
		}
	}

	// 
	//
	// register all procedures
	//
	if (addProcedure(new PccEncrypt("PCP_ENCRYPT")) != 0) {
		ATHROWnR(DgcError(SPOS,"addProcedure failed"),-1);
	}
	if (addProcedure(new PccDecrypt("PCP_DECRYPT")) != 0) {
		ATHROWnR(DgcError(SPOS,"addProcedure failed"),-1);
	}
	if (addProcedure(new PccRunJob("PCP_RUN_JOB")) != 0) {
		ATHROWnR(DgcError(SPOS,"addProcedure failed"),-1);
	}
	if (addProcedure(new PccRunMigJob("PCP_RUN_MIG_JOB")) != 0) {
		ATHROWnR(DgcError(SPOS,"addProcedure failed"),-1);
	}
	if (addProcedure(new PccRunVerify("PCP_RUN_VERIFY")) != 0) {
		ATHROWnR(DgcError(SPOS,"addProcedure failed"),-1);
	}
	if (addProcedure(new PccRunMigVerify("PCP_RUN_MIG_VERIFY")) != 0) {
		ATHROWnR(DgcError(SPOS,"addProcedure failed"),-1);
	}
	if (addProcedure(new PccStopJob("PCP_STOP_JOB")) != 0) {
		ATHROWnR(DgcError(SPOS,"addProcedure failed"),-1);
	}
	if (addProcedure(new PccRunSchedule("PCP_RUN_SCHEDULE")) != 0) {
		ATHROWnR(DgcError(SPOS,"addProcedure failed"),-1);
	}
	if (addProcedure(new PccRunMigSchedule("PCP_RUN_MIG_SCHEDULE")) != 0) {
		ATHROWnR(DgcError(SPOS,"addProcedure failed"),-1);
	}
	if (addProcedure(new PccRunVerifySchedule("PCP_RUN_VERIFY_SCHEDULE")) != 0) {
		ATHROWnR(DgcError(SPOS,"addProcedure failed"),-1);
	}
	if (addProcedure(new PccRunMigVerifySchedule("PCP_RUN_MIG_VERIFY_SCHEDULE")) != 0) {
		ATHROWnR(DgcError(SPOS,"addProcedure failed"),-1);
	}
	if (addProcedure(new PccJobProgress("PCP_JOB_PROGRESS")) != 0) {
		ATHROWnR(DgcError(SPOS,"addProcedure failed"),-1);
	}
	return 0;
}


dgt_sint32 PccJobMgrFactory::finalize() throw(DgcExcept)
{
	return 0;
}


dgt_void initServerFactory()
{
	static PccJobMgrFactory	JobMgrFactory;     // create a JobMgrFactory
	DgcProcServer::initFactory(&JobMgrFactory);        // register the JobMgrFactory with the Procedure Server
}
