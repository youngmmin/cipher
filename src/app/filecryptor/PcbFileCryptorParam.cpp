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

void PcbFileCryptorParam::setCheckMode() { mode = FCB_MODE_CHECK; }

int PcbFileCryptorParam::toString(char *param_list, int param_list_size) {
    memset(param_list, 0, param_list_size);

    char mode[10];
    memset(mode, 0, sizeof(mode));

    switch (this->mode) {
        case FCB_MODE_ENCRYPT:
            strcpy(mode, "encrypt");
            break;
        case FCB_MODE_DECRYPT:
            strcpy(mode, "decrypt");
            break;
        default:
            break;
    }

    sprintf(param_list,
            "(key=(1=(name=%s)(columns=1)))(mode=(crypt=%s)(overwrite_flag=on))"
            "(session=(program_id=%s run pcb_filecryptor))",
            key_name, mode, user);

    return 0;
}