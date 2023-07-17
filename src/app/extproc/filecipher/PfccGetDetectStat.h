/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccGetDetectStat
 *   Implementor        :       mjkim
 *   Create Date        :       2020. 08. 12
 *   Description        :       get file detection stat
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_GET_DETECT_STAT_H
#define PFCC_GET_DETECT_STAT_H

#include "DgcExtProcedure.h"
#include "DgcSqlHandle.h"
#include "DgcMemRows.h"
#include "PccHashTable.h"
#include "DgcCRC64.h"

typedef struct {
	dgt_sint64	file_id;
	dgt_sint64	pttn_num;
	dgt_sint64	pttn_files;
	dgt_schar	path[2048];
} pfcc_detect_stat;

class PfccGetDetectStat : public DgcExtProcedure {
  private:
	static const dgt_sint32 DETECT_NODE_HASH_SIZE = 3000;
	PccHashTable	DetectStat;
  protected:
  public:
	PfccGetDetectStat(const dgt_schar* name);
	virtual ~PfccGetDetectStat();
	virtual DgcExtProcedure* clone();

	virtual dgt_sint32 initialize() throw(DgcExcept);
	virtual dgt_sint32 execute() throw(DgcExcept);
	virtual dgt_sint32 fetch() throw(DgcExcept);

	pfcc_detect_stat* getDetectStat(dgt_schar* path);
};


#endif
