/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccKredServer
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 13
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccKredService.h"


static const dgt_sint32	DGC_IN_TIMEOUT	=60;	// communication stream input default timeout until authentication
static const dgt_sint32	DGC_OUT_TIMEOUT	=60;	// communication stream output default timeout until authentication


int main(dgt_sint32 argc,dgt_schar** argv)
{
	//
	// 1. initialize process
	//
	if (DgcDbProcess::initialize(DGC_WT_DB_SERVICE,"kred_service",1,1) != 0) {
		EXCEPT->print();
		exit(1);
	}
	dg_signal(SIGCHLD,SIG_IGN);

	DgcExcept*	e=0;
	for(;;) {
		//
		// 2. compile connect string
		//
		if (argc != 2) {
			e=new DgcDbNetExcept(DGC_EC_DN_INVALID_CS,new DgcError(SPOS,"invalid the number of args[%d]",argc));
			break;
		}
		DgcBgrammer	bg;
		if (bg.parse(argv[1]) < 0 || bg.pstatus() != DGC_BGPS_FINISH) {
			if (EXCEPT != 0) {
				e=EXCEPTnC;
				e->addErr(new DgcError(SPOS,"parse[%s] failed",argv[1]));
			} else {
				e=new DgcBgmrExcept(DGC_EC_BG_INCOMPLETE,
					new DgcError(SPOS,"incomplete connect string[%s]",argv[1]));
			}
			break;
		}
		dgt_schar*	protocol;
		if ((protocol=bg.getValue("ADDRESS.PROTOCOL")) == 0) {
			e=new DgcDbNetExcept(DGC_EC_DN_INVALID_CS,
				new DgcError(SPOS,"'ADDRESS.PROTOCOL' not found in [%s]",argv[1]));
			break;
		}
		dgt_sint32	D[2];				// pipe descriptors for communication stream
		dgt_schar	tmp[32];
		dgt_schar*	end_ptr=0;
		dgt_schar*	tk=dg_getenv("DG_IO_DESC_SVR");	// string holding the two numbers of pipe descriptors: 10,12
		if (tk == 0) {
			e=new DgcDbNetExcept(DGC_EC_DN_INVALID_CS,new DgcError(SPOS,"env[DG_IO_DESC_SVR] not defined"));
			break;
		}
		dg_strcpy(tmp,tk);
		if ((tk=strtok(tmp,", ")) != 0) {
			D[0]=strtol(tk,&end_ptr,10);
			if (*end_ptr != 0) {
				e=new DgcDbNetExcept(DGC_EC_DN_INVALID_CS,
					new DgcError(SPOS,"invalid number format in [%s]",tmp));
				break;
			}
		} else {
			e=new DgcDbNetExcept(DGC_EC_DN_INVALID_CS,
				new DgcError(SPOS,"invalid descriptors format[%s]",dg_getenv("DG_IO_DESC_SVR")));
			break;
		}
		if ((tk=strtok(0,", \n"))) {
			D[1]=strtol(tk,&end_ptr,10);
			if (*end_ptr != 0) {
				e=new DgcDbNetExcept(DGC_EC_DN_INVALID_CS,
					new DgcError(SPOS,"invalid number format in [%s]",tmp));
				break;
			}
		} else {
			e=new DgcDbNetExcept(DGC_EC_DN_INVALID_CS,
				new DgcError(SPOS,"invalid descriptors format[%s]",dg_getenv("DG_IO_DESC_SVR")));
			break;
		}

		//
		// 3. open a communication stream from client
		//
		DgcCommStream*	comm;
		if (strcasecmp(protocol,"BEQ") == 0) {
			comm=new DgcPipeStream(D[0],D[1],DGC_IN_TIMEOUT,DGC_OUT_TIMEOUT);
		} else if (strcasecmp(protocol,"TCP") == 0 || strcasecmp(protocol,"ICP") == 0) {
			comm=new DgcSockStream(D[0],DGC_IN_TIMEOUT,DGC_OUT_TIMEOUT);
		} else {
			e=new DgcDbNetExcept(DGC_EC_DN_INVALID_CS,new DgcError(SPOS,"unsupported protocol[%s]",protocol));
			break;
		}

		//
		// 4. start a database service worker and wait for its termination
		//
		PccKredService*	kred_svc=new PccKredService(getpid(),comm);
		kred_svc->wa()->ThreadID=pthread_self();
		DgcWorker::entry((dgt_void*)kred_svc);
		break;
	}
	if (e != 0) {
		DgcWorker::PLOG.tprintf(0,*e,"PccKredService start failed due to the below exception:\n");
		delete e;
		exit(1);
	}
	exit(0);
}
