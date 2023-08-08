#include <stdio.h>
#include <string.h>

#include "DgcObject.h"

class PcbFileCryptorParam : public DgcObject {
   private:
    char *user;
    char *program_name;
    char *key_name;
    char *in_file;
    char *out_file;
    int mode;

    static const int PARAM_BUFFER_SIZE = 2048;
    static const int MODE_STRING_SIZE = 10;

    char parameter_string[PARAM_BUFFER_SIZE];

   public:
    static const int FCB_MODE_NONE = 0;
    static const int FCB_MODE_ENCRYPT = 1;
    static const int FCB_MODE_DECRYPT = 2;
    static const int FCB_MODE_PARAMETER = 3;
    static const int FCB_MODE_CHECK = 4;

    PcbFileCryptorParam();

    void setUser(const char *user_);
    void setProgramName(const char *program_name_);
    void setKeyName(const char *key_name_);
    void setInFile(const char *in_file_);
    void setOutFile(const char *out_file_);
    void setParameter(const char *parameter_string_);

    void setEncryptMode();
    void setDecryptMode();
    void setParameterMode();
    void setCheckMode();

    int getMode() { return mode; };
    int getModeString(char *mode_string_, int mode_string_size_);
    char *getInFile() { return in_file; };
    char *getOutFile() { return out_file; };

    int getParameterString(char *param_list, int param_list_size);
};