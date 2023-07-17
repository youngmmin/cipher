/*******************************************************************
 *   File Type          :       external procedure
 *   Classes            :       PfccGetFileInfo
 *   Implementor        :       sonsuhun
 *   Create Date        :       2017. 05. 24
 *   Description        :       get EncTgtSys table
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PFCC_GET_FILE_INFO_H
#define PFCC_GET_FILE_INFO_H

#include "PfccAgentProcedure.h"

typedef struct {
	dgt_sint64	agent_id;
	dgt_schar	dir_path[1024];
	dgt_sint64	offset;
	dgt_sint32	fetch_count;
} pfcc_get_file_info_in;

class PfccGetFileInfo : public PfccAgentProcedure {
  private:
  protected:
  public:
	PfccGetFileInfo(const dgt_schar* name, PfccAgentListener* agent_listener);
	virtual ~PfccGetFileInfo();
	virtual DgcExtProcedure* clone();
	virtual dgt_sint32 initialize() throw(DgcExcept);
	virtual dgt_sint32 execute() throw(DgcExcept);
//	virtual dgt_sint32 fetch() throw(DgcExcept);
};


#endif
