#include <stdio.h>
#include <string.h>
#include "DgcObject.h"

// typedef enum {
//     FCB_MODE_NONE = 0,
//     FCB_MODE_ENCRYPT = 1,
//     FCB_MODE_DECRYPT = 2,
//     FCB_MODE_CHECK = 3
// } PcbFileCryptorMode;

class PcbFileCryptorParam : public DgcObject
{
private:
    char *user;
    char *key_name;
    char *in_file;
    char *out_file;
    int mode;

    static const int FCB_MODE_NONE = 0;
    static const int FCB_MODE_ENCRYPT = 1;
    static const int FCB_MODE_DECRYPT = 2;
    static const int FCB_MODE_CHECK = 3;

public:
    PcbFileCryptorParam();

    void setUser(const char *user_);
    void setKeyName(const char *key_name_);
    void setInFile(const char *in_file_);
    void setOutFile(const char *out_file_);
    void setEncryptMode();
    void setDecryptMode();
    void setCheckMode();

    int toString(char* param_list, int param_list_size);
};