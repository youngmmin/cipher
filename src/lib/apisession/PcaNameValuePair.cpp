/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PcaNameValuePair
 *   Implementor        :       chchung
 *   Create Date        :       2012. 4. 12.
 *   Description        :       petra cipher API name value pair
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PcaNameValuePair.h"

dgt_sint32 PcaNameValuePair::parse() {
    delete First;
    First = 0;
    dgt_schar* name;
    dgt_schar* value;
    dgt_schar* op;
    dgt_schar* last;
#ifdef WIN32
    dgt_schar* line = strtok_s(Text, "\f\n", &last);
#else
    dgt_schar* line = strtok_r(Text, "\f\n", &last);
#endif
    for (dgt_sint32 line_no = 1; line; line_no++) {
        //
        // trim leading white spaces
        //
        for (dgt_sint32 i = 0; *line == ' ' || *line == '\t'; i++) line++;
        if (*line != '#') {
            //
            // split name & value by "="
            //
            op = strstr(line, "=");
            if (!op) {
                sprintf(ErrMsg, "line[%d:%s] has no =", line_no, line);
                return PNVP_PARSE_ERROR;
            }
            *op = 0;
            name = line;
            for (dgt_sint32 i = 0; *(name + i); i++)
                if (*(name + i) == ' ' || *(name + i) == '\t') {
                    *(name + i) = 0;
                    break;
                }  // trim tailing white spaces
            value = op + 1;
            for (dgt_sint32 i = 0; *value && (*value == ' ' || *value == '\t');
                 i++)
                value++;
            for (dgt_sint32 i = strlen(value) - 1; i >= 0; i--)
                if (*(value + i) == ' ' || *(value + i) == '\t')
                    *(value + i) = 0;
                else
                    break;
            addNode(name, value);
        }
#ifdef WIN32
        line = strtok_s(0, "\f\n", &last);
#else
        line = strtok_r(0, "\f\n", &last);
#endif
    }
    Cursor = First;
    return 0;
}

PcaNameValuePair::PcaNameValuePair() : Text(0), First(0), Cursor(0) {}

PcaNameValuePair::~PcaNameValuePair() {
    delete First;
    delete Text;
}

dgt_sint32 PcaNameValuePair::parse(dgt_schar* text) {
    dgt_sint32 text_len = strlen(text);
    delete Text;
    Text = new dgt_schar[text_len + 1];
    memcpy(Text, text, text_len);
    *(Text + text_len) = 0;
    return parse();
}

dgt_sint32 PcaNameValuePair::parseFromFile(dgt_schar* file_path) {
    dgt_sint32 fd;
    if ((fd = open(file_path, O_RDONLY)) < 0) {
        sprintf(ErrMsg, "open[%s] failed, os_error[%d:%s]", file_path, errno,
                strerror(errno));
        return PNVP_FILE_ERROR;
    }
    struct stat fst;
    if (fstat(fd, &fst) < 0) {
        sprintf(ErrMsg, "fstat[%s] failed, os_error[%d:%s]", file_path, errno,
                strerror(errno));
        close(fd);
        return PNVP_FILE_ERROR;
    }
    delete Text;
    Text = new dgt_schar[fst.st_size + 1];
    memset(Text, 0, fst.st_size + 1);
    dgt_sint32 rbytes;
    if ((rbytes = read(fd, Text, fst.st_size)) < 0) {
        sprintf(ErrMsg, "read[%s] failed, os_error[%d:%s]", file_path, errno,
                strerror(errno));
        close(fd);
        return PNVP_FILE_ERROR;
    }
    close(fd);
    return parse();
}

dgt_schar* PcaNameValuePair::getValue(const dgt_schar* name,
                                      dgt_sint8 is_case_sensitive) {
    PcaNameValueNode* curr = First;
    while (curr) {
        if (is_case_sensitive) {
            if (!strcmp(name, curr->name())) return curr->value();
        } else {
            if (!strcasecmp(name, curr->name())) return curr->value();
        }
        curr = curr->next();
    }
    return 0;
}

#if 0
int main(int argc, char** argv)
{
	PcaNameValuePair	nvp;
	dgt_sint32		rtn;
	if ((rtn=nvp.parseFromFile(argv[1]))) {
		printf("parse[%s] error[%d:%s]\n",argv[1],rtn,nvp.errMsg());
		exit(1);
	}
	dgt_schar*	name=0;
	while((name=nvp.next())) {
		dgt_schar*	val=nvp.getValue(name);
		printf("name[%s] value[%s] getValue[%s]\n",name,nvp.value(),val);
	}
}
#endif
