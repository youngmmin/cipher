/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PetraCipherMigVerifyJob
 *   Implementor        :       mwpark
 *   Create Date        :       2015. 09. 03
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PETRA_CIPHER_MIG_VERIFY_JOB_H
#define PETRA_CIPHER_MIG_VERIFY_JOB_H


#include "DgcPetraWorker.h"
#include "PccTableTypes.h"

class PetraCipherMigVerifyJob : public DgcPetraWorker {
  private:
	dgt_sint64		JobID;
	dgt_sint64		EncTabID;

	pct_type_enc_table	EncTabRow;
	DgcTableSegment*	JobSeg;
	DgcRowRef		AllJobRows;
	DgcRowList		JobRows;
	pct_type_verify_job*	JobRowPtr;

	dgt_sint32		initJobRows() throw(DgcExcept);
	dgt_void		setPending(DgcExcept* e);
	dgt_sint32		getEncTabRow() throw(DgcExcept);
	dgt_void		commitJobRows();

	virtual dgt_void	in() throw(DgcExcept);
	virtual dgt_sint32	run() throw(DgcExcept);
	virtual dgt_void	out() throw(DgcExcept);
  protected:
  public:
	static const dgt_sint16	PCB_JOB_STATUS_SCHEDULING=0;
	static const dgt_sint16	PCB_JOB_STATUS_PENDING=10000;
	static const dgt_sint16	PCB_JOB_STATUS_DONE=20000;

        PetraCipherMigVerifyJob(
			dgt_sint64 job_id,
			dgt_sint64 enc_tab_id=0);
        virtual ~PetraCipherMigVerifyJob();
};


#endif
