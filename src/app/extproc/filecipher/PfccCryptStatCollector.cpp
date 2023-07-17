/*******************************************************************
 *   File Type          :       worker file
 *   Classes            :       PfccCryptStatCollector
 *   Implementor        :       shson
 *   Create Date        :       2018. 3. 13
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 1
#define DEBUG
#endif

#include "PfccCryptStatCollector.h"


PfccCryptStatCollector::PfccCryptStatCollector(dgt_worker* wa, PfccAgentListener* agent_listener, dgt_sint32 collecting_interval)
	: DgcPetraWorker(DGC_WT_CIPHER_AGENT_PROC_SVR,"pfcc_crypt_stat_collector",wa)
{
	AgentListener = agent_listener;
	if (collecting_interval > 0) CollectingInterval = collecting_interval;
	else CollectingInterval = 5;
}


PfccCryptStatCollector::~PfccCryptStatCollector()
{
}


dgt_void PfccCryptStatCollector::in() throw(DgcExcept)
{
	DgcWorker::PLOG.tprintf(0,"CryptStatCollector is starting.\n");
}


dgt_sint32 PfccCryptStatCollector::run() throw(DgcExcept)
{
#define MAXSQLLEN 1024
//	DgcWorker::PLOG.tprintf(0,"CryptStatCollector is running.\n");
	DgcSqlHandle sql_handle(DgcDbProcess::sess()); // for select agent_id,enc_job_id,enc_zone_id,enc_job_tgt_id
	dgt_schar stext[MAXSQLLEN];
	memset(stext,0,MAXSQLLEN);
	sprintf(stext,
			"select b.agent_id, a.enc_job_id, a.enc_zone_id,a.enc_job_tgt_id "
			"from pfct_enc_job_tgt a,pfct_enc_job b "
			"where a.enc_job_id = b.enc_job_id "
			"and a.status in (1,3) and b.status = 1 "
			);
	if (sql_handle.execute(stext,dg_strlen(stext)) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);
	dgt_sint32 ret = 0; // for sql_handle
	dgt_void* rtn_row = 0; // for sql_handle
	dgt_sint32 ret2 = 0; //for procedure_handle
	dgt_void* rtn_row2 = 0; //for procedure_handle
	pfcc_get_dir_crypt_stat_in* get_dir_crypt_stat_in = 0;
	pcct_crypt_stat* get_dir_crypt_stat_out = 0;
	PfccAgentSession* AgentSession = 0;

	while (!(ret = sql_handle.fetch(rtn_row)) && rtn_row) { 
		//exist target directory
		if (ret < 0) ATHROWnR(DgcError(SPOS,"fetch failed"), -1);
		if (rtn_row) get_dir_crypt_stat_in = (pfcc_get_dir_crypt_stat_in*)rtn_row;
#if 1/*{{{*/
		//check connection agent session
	AgentSession = AgentListener->agentSessPool().getSession(get_dir_crypt_stat_in->agent_id);
	if (AgentSession == 0) {
		napAtick();
		continue;
		//THROWnR(DgcDgExcept(DGC_EC_DG_INVALID_STAT,new DgcError(SPOS,"agent[%lld] has no available session\n",get_dir_crypt_stat_in->agent_id)),-1);
	}
	if (AgentSession) AgentListener->agentSessPool().returnSession(AgentSession);
	//call PFC_GET_DIR_CRYPT_STAT
	DgcSqlHandle procedure_handle(DgcDbProcess::sess());
	memset(stext,0,MAXSQLLEN);
	sprintf(stext,"select * from  PFC_GET_DIR_CRYPT_STAT(%lld, %lld, %lld, %lld)",
				get_dir_crypt_stat_in->agent_id,
				get_dir_crypt_stat_in->job_id,
				get_dir_crypt_stat_in->enc_zone_id,
				get_dir_crypt_stat_in->enc_job_tgt_id
		   );
	if (procedure_handle.execute(stext,dg_strlen(stext)) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);

	while (!(ret2 = procedure_handle.fetch(rtn_row2)) && rtn_row2) { 
		if (ret2 < 0) ATHROWnR(DgcError(SPOS,"fetch failed"), -1);
		if (rtn_row2) get_dir_crypt_stat_out = (pcct_crypt_stat*)rtn_row2;

		//delete row for update
	DgcSqlHandle dml_handle(DgcDbProcess::sess());
	memset(stext,0,MAXSQLLEN);
	sprintf(stext,"delete pfct_crypt_stat_temp  "
				  "where job_id = %lld "
				  "and dir_id = %lld "
				  "and agent_id = %lld "
				  "and zone_id = %lld "
				  ,get_dir_crypt_stat_out->job_id 
				  ,get_dir_crypt_stat_out->dir_id
				  ,get_dir_crypt_stat_out->agent_id
				  ,get_dir_crypt_stat_out->zone_id
		   );
	if (dml_handle.execute(stext,dg_strlen(stext)) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);
	//insert new row
	memset(stext,0,MAXSQLLEN);
	sprintf(stext,"insert into pfct_crypt_stat_temp values("
				  "%lld, %lld, %lld, %lld, %lld, %lld, %lld, %lld, %lld, %lld, 	" /* job_id ~ target_files 	*/
				  "%lld, %lld, %lld, %lld, %lld, %lld, %lld, %lld, 	 %u,   %u,	" /* input_files ~ end_time */
				  "	 %d,   %d, %lld, %lld) 										" /* job_status ~ reserved	*/
				  ,get_dir_crypt_stat_out->job_id 
				  ,get_dir_crypt_stat_out->dir_id
				  ,get_dir_crypt_stat_out->agent_id
				  ,get_dir_crypt_stat_out->zone_id
				  ,get_dir_crypt_stat_out->filters     
				  ,get_dir_crypt_stat_out->check_dirs  
				  ,get_dir_crypt_stat_out->check_errors
				  ,get_dir_crypt_stat_out->target_dirs 
				  ,get_dir_crypt_stat_out->check_files 
				  ,get_dir_crypt_stat_out->target_files
				  ,get_dir_crypt_stat_out->input_files 
				  ,get_dir_crypt_stat_out->output_files
				  ,get_dir_crypt_stat_out->crypt_errors
				  ,get_dir_crypt_stat_out->used_cores  
				  ,get_dir_crypt_stat_out->used_micros 
				  ,get_dir_crypt_stat_out->input_bytes 
				  ,get_dir_crypt_stat_out->output_bytes
				  ,get_dir_crypt_stat_out->system_id
				  ,get_dir_crypt_stat_out->start_time  
				  ,get_dir_crypt_stat_out->end_time    
				  ,get_dir_crypt_stat_out->job_status  
				  ,get_dir_crypt_stat_out->dir_status  
				  ,get_dir_crypt_stat_out->migration_target
				  ,get_dir_crypt_stat_out->reserved
		   );
	if (dml_handle.execute(stext,dg_strlen(stext)) < 0) ATHROWnR(DgcError(SPOS,"execute failed"), -1);
		//DgcWorker::PLOG.tprintf(0,"insert success\n");
	} //procedure_handle.fetch end
	napAtick();
#endif/*}}}*/
	} //sql_handle.fetch end
	sleep(CollectingInterval);
	return 0;
}


dgt_void PfccCryptStatCollector::out() throw(DgcExcept)
{
	DgcWorker::PLOG.tprintf(0,"CryptStatCollector is stopped.\n");
}

