/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PcbSelectStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcbSelectStmt.h"


PcbSelectStmt::PcbSelectStmt(PcbCipherTable* cipher_table,dgt_uint32 array_size)
	: PcbStmt(cipher_table,array_size),
	  TotalRows(0),
	  NumFetchCols(0),
	  NumFetchedRows(0)
{
	for(dgt_uint32 i=0; i<PCB_MAX_FETCH_COLS; i++) FetchColAttrs[i]=0;
}


PcbSelectStmt::~PcbSelectStmt()
{
	for(dgt_uint32 i=0; i<NumFetchCols; i++) delete FetchColAttrs[i];
}
