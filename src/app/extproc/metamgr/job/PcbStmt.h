/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcbStmt
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCB_STMT_H
#define PCB_STMT_H


#include "PcbCipherTable.h"

class PcbStmt : public DgcObject {
  private:
	static const dgt_uint32 PCB_ARRAY_SIZE=1000;
  protected:
	PcbCipherTable*	CipherTable;
	dgt_uint32	ArraySize;
	dgt_schar*	SqlText;
  public:
        PcbStmt(PcbCipherTable* cipher_table, dgt_uint32 array_size=0)
		: CipherTable(cipher_table),
		  ArraySize(array_size),
		  SqlText(0)
	{
		if (ArraySize == 0) ArraySize=PCB_ARRAY_SIZE;
	};

        virtual ~PcbStmt() { if(SqlText) delete SqlText; };

	inline dgt_uint32 arraySize() { return ArraySize; };
	inline const dgt_schar* sqlText() { return SqlText; };
};


#endif
