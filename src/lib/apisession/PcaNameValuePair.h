/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcaNameValuePair
 *   Implementor        :       chchung
 *   Create Date        :       2012. 4. 12.
 *   Description        :       petra cipher API name value pair
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCA_NAME_VALUE_PAIR_H
#define PCA_NAME_VALUE_PAIR_H

#include "DgcObject.h"

class PcaNameValuePair {
   private:
    static const dgt_sint32 PNVP_PARSE_ERROR = -30315;
    static const dgt_sint32 PNVP_FILE_ERROR = -30316;

    class PcaNameValueNode {
       private:
        dgt_schar* Name;
        dgt_schar* Value;
        PcaNameValueNode* Next;

       public:
        PcaNameValueNode(dgt_schar* name, dgt_schar* value)
            : Name(name), Value(value), Next(0){};
        virtual ~PcaNameValueNode() { delete Next; };

        inline dgt_schar* name() { return Name; };
        inline dgt_schar* value() { return Value; };
        inline PcaNameValueNode* next() { return Next; };
        inline dgt_void setNext(PcaNameValueNode* next = 0) { Next = next; };
    };

    dgt_schar* Text;
    PcaNameValueNode* First;
    dgt_schar ErrMsg[256];
    PcaNameValueNode* Cursor;

    inline dgt_void addNode(dgt_schar* name, dgt_schar* value) {
        PcaNameValueNode* tmp = new PcaNameValueNode(name, value);
        tmp->setNext(First);
        First = tmp;
    };

    dgt_sint32 parse();

   protected:
   public:
    PcaNameValuePair();
    virtual ~PcaNameValuePair();

    inline dgt_schar* errMsg() { return ErrMsg; };
    inline dgt_void setCursor() { Cursor = First; };
    inline dgt_schar* next() {
        if (Cursor) Cursor = Cursor->next();
        if (Cursor) return Cursor->name();
        return 0;
    };
    inline dgt_schar* name() {
        if (Cursor) return Cursor->name();
        return 0;
    };
    inline dgt_schar* value() {
        if (Cursor) return Cursor->value();
        return 0;
    };

    dgt_sint32 parse(dgt_schar* text);
    dgt_sint32 parseFromFile(dgt_schar* file_path);
    dgt_schar* getValue(const dgt_schar* name, dgt_sint8 is_case_sensitive = 0);
};

#endif
