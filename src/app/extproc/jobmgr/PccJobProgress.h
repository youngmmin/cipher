
/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccJobProgress
 *   Implementor        :       jhpark
 *   Create Date        :       2013. 5. 6
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_JOB_PROGRESS
#define PCC_JOB_PROGRESS


#include "DgcExtProcedure.h"
#include "DgcDatabaseLink.h"

typedef struct{
	dgt_sint16 curr_enc_step;
	dgt_sint16 curr_enc_stmt;
	dgt_sint16 curr_status;
	dgt_sint64 total_rows;
	dgt_sint64 enc_tab_id;
	dgt_uint8  init_enc_type;
} pct_type_job_progress_curr_info;

typedef struct{
	dgt_sint16 	curr_enc_step;
	dgt_sint16 	curr_enc_stmt;
	dgt_sint16 	curr_status;
	dgt_float64 progress_status;
	dgt_schar	remark[129];
} pct_type_job_progress_result;

typedef struct{
	dgt_sint64 schema_name;
	dgt_sint64 enc_table_size;
	dgt_sint64 db_link;
} pct_type_job_progress_ctable_info;

class PccJobProgress : public DgcExtProcedure {
  private:
	DgcDatabaseLink* DatabaseLink;
  protected:
  public:
	PccJobProgress(const dgt_schar* name);
	virtual ~PccJobProgress();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 execute() throw(DgcExcept);
};

#endif /* PCC_JOB_PROGRESS */
