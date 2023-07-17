/*******************************************************************
 *   File Type          :       hash table classes definition
 *   Classes            :       PccHashTable
 *   Implementor        :       chchung
 *   Create Date        :       2017. 06. 30
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccHashTable.h"

PccHashNode* PccHashTable::getFreeNode(dgt_uint64 key,dgt_void* value)
{
	PccHashNode* node = FirstFree;
	if (node) {
		if ((FirstFree=node->next()) == 0) LastFree=0;
	} else {
		while ((node=(PccHashNode*)NodePool[CurrList]->getObject()) == 0) {
			if ((CurrList+1) == MAX_LISTS) break;
			NodePool[++CurrList] = new PtChunkObjectList(sizeof(PccHashNode));
		}
	}
	if (node) node->reset(key,value);
	return node;
}

PccHashTable::PccHashTable(dgt_sint32 size)
	: Size(size),FirstFree(0),LastFree(0),CurrPos(-1),CurrNode(0),CurrList(0)
{
	Table = new PccHashNode*[Size];
	memset(Table,0,sizeof(PccHashNode*)*Size);
	NodePool[CurrList] = new PtChunkObjectList(sizeof(PccHashNode));
}

PccHashTable::~PccHashTable()
{
	for(dgt_sint32 i=0; i<=CurrList; i++) delete NodePool[i];
	delete[] Table;
}

PccHashNode* PccHashTable::addNode(dgt_uint64 key,dgt_void* value)
{
	PccHashNode*	node = getFreeNode(key,value);
	if (node) {
		dgt_uint32	pos = key % Size;
		node->setNext(Table[pos]);
		Table[pos] = node;
	}
	return node;
}

PccHashNode* PccHashTable::findNode(dgt_uint64 key)
{
	PccHashNode*	node = Table[key % Size];
	while (node) {
		if (node->key() == key) return node;
		node = node->next();
	}
	return 0;
}

dgt_sint32 PccHashTable::removeNode(dgt_uint64 key)
{
	PccHashNode*	prev = 0;
	PccHashNode*	curr = Table[key % Size];
	while (curr) {
		if (curr->key() == key) {
			if (prev == 0) Table[key % Size] = curr->next();
			else prev->setNext(curr->next());
			curr->reset();
			if (LastFree) LastFree->setNext(curr);
			else FirstFree = curr;
			LastFree = curr;
			return 1;
		}
		prev = curr;
		curr = curr->next();
	}
	return 0;
}

PccHashNode* PccHashTable::nextNode()
{
	while(CurrNode == 0) {
		if ((CurrPos+1) == Size) return 0; // end of table
		CurrNode = Table[CurrPos=(CurrPos+1)];
	}
	PccHashNode* rtn = CurrNode;
	CurrNode = CurrNode->next();
	return rtn;
}
