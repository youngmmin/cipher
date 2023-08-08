#include "PcbFileCryptorParam.h"

PcbFileCryptorParam::PcbFileCryptorParam()
    : user(NULL),
      key_name(NULL),
      in_file(NULL),
      out_file(NULL),
      mode(FCB_MODE_NONE) {}

void PcbFileCryptorParam::setUser(const char *user_) {
    if (user != NULL) {
        delete[] user;
    }
    user = new char[strlen(user_) + 1];
    strcpy(user, user_);
}

void PcbFileCryptorParam::setProgramName(const char *program_name_) {
    if (program_name != NULL) {
        delete[] program_name;
    }
    program_name = new char[strlen(program_name_) + 1];
    strcpy(program_name, program_name_);
}

void PcbFileCryptorParam::setKeyName(const char *key_name_) {
    if (key_name != NULL) {
        delete[] key_name;
    }
    key_name = new char[strlen(key_name_) + 1];
    strcpy(key_name, key_name_);
}

void PcbFileCryptorParam::setInFile(const char *in_file_) {
    if (in_file != NULL) {
        delete[] in_file;
    }
    in_file = new char[strlen(in_file_) + 1];
    strcpy(in_file, in_file_);
}

void PcbFileCryptorParam::setOutFile(const char *out_file_) {
    if (out_file != NULL) {
        delete[] out_file;
    }
    out_file = new char[strlen(out_file_) + 1];
    strcpy(out_file, out_file_);
}

void PcbFileCryptorParam::setEncryptMode() { mode = FCB_MODE_ENCRYPT; }

void PcbFileCryptorParam::setDecryptMode() { mode = FCB_MODE_DECRYPT; }

void PcbFileCryptorParam::setParameterMode() { mode = FCB_MODE_PARAMETER; }

void PcbFileCryptorParam::setCheckMode() { mode = FCB_MODE_CHECK; }

void PcbFileCryptorParam::setParameter(const char *parameter_string_) {
    if (strlen(parameter_string_) > PARAM_BUFFER_SIZE) {
        printf("ERROR: parameter_string_ is too long. It must be at most %d.\n",
               PARAM_BUFFER_SIZE);
        return;
    }

    memset(parameter_string, 0, PARAM_BUFFER_SIZE);
    strncpy(parameter_string, parameter_string_, strlen(parameter_string_));
    parameter_string[strlen(parameter_string_)] = '\0';
}

int PcbFileCryptorParam::getModeString(char *mode_string_,
                                       int mode_string_size_) {
    switch (getMode()) {
        case FCB_MODE_ENCRYPT:
            strncpy(mode_string_, "encrypt", mode_string_size_);
            break;
        case FCB_MODE_DECRYPT:
            strncpy(mode_string_, "decrypt", mode_string_size_);
            break;
        case FCB_MODE_PARAMETER:
            strncpy(mode_string_, "parameter", mode_string_size_);
            break;
        case FCB_MODE_CHECK:
            strncpy(mode_string_, "check", mode_string_size_);
            break;
        default:
            break;
    }
}

int PcbFileCryptorParam::getParameterString(char *param_string_,
                                            int param_buffer_size_) {
    if (param_buffer_size_ < PARAM_BUFFER_SIZE) {
        printf("ERROR: param_list_size is too small. It must be at least %d.\n",
               PARAM_BUFFER_SIZE);
        return -1;
    }

    if (getMode() == FCB_MODE_ENCRYPT || getMode() == FCB_MODE_DECRYPT) {
        char _parameter_string[PARAM_BUFFER_SIZE];
        memset(_parameter_string, 0, PARAM_BUFFER_SIZE);

        char mode_string[MODE_STRING_SIZE];
        memset(mode_string, 0, MODE_STRING_SIZE);
        getModeString(mode_string, MODE_STRING_SIZE);

        sprintf(_parameter_string,
                "(file=(in=%s)(out=%s)(log=%s.log))"
                "(key=(1=(name=%s)(columns=1)))"
                "(mode=(crypt=%s)(overwrite_flag=on)(header_flag=V2on))"
                "(session=(program_id=%s_exec_%s))",
                in_file, out_file, program_name, key_name, mode_string, user,
                program_name);

        setParameter(_parameter_string);
    }

    memset(param_string_, 0, param_buffer_size_);
    strncpy(param_string_, parameter_string, PARAM_BUFFER_SIZE);

    return 0;
}
