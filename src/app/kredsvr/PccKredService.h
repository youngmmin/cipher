/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredService
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 16
 *   Description        :       
 *   Modification history	key service
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_KRED_SERVICE_H
#define PCC_KRED_SERVICE_H


#include "DgcDbService.h"


class PccKredService : public DgcDbService {
  private:
	dgt_uint8		OpenFlag;

	dgt_sint8		doRequest(DgcMsgDgiSqlRq* srm) throw(DgcExcept);
	dgt_sint8		doResponse(DgcMsgDgiSqlRq* srm) throw(DgcExcept);
	virtual dgt_sint32	run() throw(DgcExcept);
  protected:
  public:
	PccKredService(pid_t pid, DgcCommStream* comm_stream);
	virtual ~PccKredService();
};


#endif
