#include "PccFileMemMap.h"

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("usage : ./pcp_trace_changer <PetraTrace.conf path> <level>\n");
        printf("example : ./pcp_trace_changer ./PetraTrace.conf 1\n");
        exit(-1);
    }

    dgt_schar* trace_conf_path = argv[1];
    dgt_uint8 trace_level = atoi(argv[2]);
    dgt_sint32 nResult = access(trace_conf_path, 0);
    if (nResult != 0) {
        printf("not exist config file :[%s]\n", trace_conf_path);
        exit(-1);
    }
    printf("trace_conf_path [%s], trace_level [%d] \n", trace_conf_path,
           trace_level);
    PccFileMemMap TraceMemMap;
    if (TraceMemMap.load(trace_conf_path, 1, 0) < 0) {
        printf("load failed");
        delete EXCEPTnC;
    }

    if (TraceMemMap.sync(&trace_level, 1) < 0) {
        printf("sync failed");
        exit(-1);
    }

    return 0;
}
