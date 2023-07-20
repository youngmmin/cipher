/*******************************************************************
 *   File Type          :       main file
 *   Classes            :       PccKeyControl
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 11. 14
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "DgcAuthEntity.h"
#include "DgcSohaConnection.h"

template <class C>
class PccAutoPtr {
   private:
    C* Pointer;

   public:
    PccAutoPtr(C* ptr = 0) : Pointer(ptr){};
    ~PccAutoPtr() { delete Pointer; };
};

class PccCmdOption {
   private:
    static const dgt_sint32 DGC_MAX_CMD_OPTIONS = 500;
    typedef struct {
        const dgt_schar* name;
        const dgt_schar* value;
    } dgt_cmd_option;

    dgt_cmd_option Options[DGC_MAX_CMD_OPTIONS];
    dgt_sint32 NumOptions;

   protected:
   public:
    PccCmdOption(dgt_sint32 argc, dgt_schar** argv) {
        dgt_sint32 curr_option = -1;
        NumOptions = 0;
        for (dgt_sint32 i = 0; i < argc && i < DGC_MAX_CMD_OPTIONS; i++) {
            if (argv[i][0] == '-') {
                Options[curr_option = NumOptions++].name = argv[i] + 1;
                Options[curr_option].value = "";
            } else {
                if (curr_option >= 0) Options[curr_option].value = argv[i];
                curr_option = -1;
            }
        }
    };
    ~PccCmdOption(){};

    inline const dgt_schar* optionValue(const dgt_schar* option_name) {
        for (dgt_sint32 i = 0; i < NumOptions; i++) {
            if (!strcasecmp(option_name, Options[i].name))
                return Options[i].value;
        }
        return 0;
    }
};

class PccCmd {
   private:
   protected:
    PccCmdOption& CmdOption;
    DgcSohaConnection Connection;

    inline dgt_sint32 connect() {
        const dgt_schar* proto = CmdOption.optionValue("proto");
        if (!proto) {
            THROWnR(DgcCipherExcept(-10001,
                                    new DgcError(SPOS, "protocol not found")),
                    -1);
        }
        dgt_schar con_string[256];
        if (!strcasecmp(proto, "beq")) {
            dg_sprintf(con_string, "(address=(protocol=beq))");
        } else if (!strcasecmp(proto, "tcp")) {
            const dgt_schar* host = CmdOption.optionValue("host");
            const dgt_schar* port = CmdOption.optionValue("port");
            if (!host) {
                THROWnR(DgcCipherExcept(-10002,
                                        new DgcError(SPOS, "host not found")),
                        -1);
            }
            if (!port) {
                THROWnR(DgcCipherExcept(-10003,
                                        new DgcError(SPOS, "port not found")),
                        -1);
            }
            dg_sprintf(con_string, "(address=(protocol=tcp)(host=%s)(port=%s))",
                       host, port);
        } else {
            THROWnR(DgcCipherExcept(
                        -10004,
                        new DgcError(SPOS, "unsupported protocol[%s]", proto)),
                    -1);
        }
        const dgt_schar* svc = CmdOption.optionValue("svc");
        if (!svc) {
            THROWnR(
                DgcCipherExcept(-10005, new DgcError(SPOS, "svc not found")),
                -1);
        }
        const dgt_schar* user = CmdOption.optionValue("user");
        if (!user) {
            THROWnR(
                DgcCipherExcept(-10006, new DgcError(SPOS, "user not found")),
                -1);
        }
        dgt_schar pw[33];
        dg_print("%s ", user);
        fflush(stdout);
        memset(pw, 0, 33);
        if (UI_UTIL_read_pw_string(pw, 32, "passwd: ", 0)) {
            THROWnR(DgcCipherExcept(
                        -10007,
                        new DgcError(SPOS, "UI_UTIL_read_pw_string failed")),
                    -1);
        }
        if (Connection.connect(con_string, svc, user, pw, "pcp_key_ctrl")) {
            ATHROWnR(DgcError(SPOS, "connect failed"), -1);
        }
        DgcCliStmt* stmt = 0;
        if ((stmt = Connection.getStmt()) == 0) {
            ATHROWnR(DgcError(SPOS, "connect failed"), -1);
        }
        dgt_sint32 frows = 0;
        dgt_schar sql_text[128];
        dg_sprintf(sql_text, "open database attach %s", svc);
        if ((frows = stmt->execute(sql_text, strlen(sql_text))) < 0) {
            ATHROWnR(DgcError(SPOS, "execute failed"), -1);
        }
        stmt->close();
        return 0;
    };

    inline dgt_sint32 runSQL(dgt_schar* sql_text, DgcMemRows* bind_rows = 0,
                             DgcFileStream* fs = 0) throw(DgcExcept) {
        if (connect()) {
            ATHROWnR(DgcError(SPOS, "connect failed"), -1);
        }
        DgcCliStmt* stmt = 0;
        if ((stmt = Connection.getStmt()) == 0) {
            ATHROWnR(DgcError(SPOS, "getStmt failed"), -1);
        }
        dgt_sint32 frows = 0;
        if ((frows = stmt->execute(sql_text, strlen(sql_text), 1, bind_rows)) <
            0) {
            DgcExcept* e = EXCEPTnC;
            delete stmt;
            RTHROWnR(e, DgcError(SPOS, "execute failed"), -1);
        }
        dgt_uint32 prows = 0;
        while (frows > 0) {
            DgcMemRows* rows = stmt->returnRows();
            if (rows == 0) {
                DgcExcept* e = EXCEPTnC;
                delete stmt;
                RTHROWnR(e, DgcError(SPOS, "returnRows failed"), -1);
            } else {
                while (rows->next()) {
                    if (fs) {
                        if (fs->sendData(rows->data(),
                                         strlen((dgt_schar*)rows->data())) <
                            0) {
                            DgcExcept* e = EXCEPTnC;
                            delete stmt;
                            RTHROWnR(e, DgcError(SPOS, "sendData failed"), -1);
                        }
                    } else
                        dg_print("%s", (dgt_schar*)rows->data());
                    prows++;
                }
                rows->reset();
            }
            frows = stmt->fetch(10);
        }
        delete EXCEPTnC;
        delete stmt;
        Connection.disconnect();
        if (prows == 1) dg_print("\n");
        return 0;
    };

   public:
    PccCmd(PccCmdOption& cmd_option) : CmdOption(cmd_option){};
    virtual ~PccCmd(){};
    virtual dgt_sint32 run() = 0;
};

class PccCmdHelp : public PccCmd {
   private:
   protected:
   public:
    PccCmdHelp(PccCmdOption& cmd_option) : PccCmd(cmd_option){};
    virtual ~PccCmdHelp(){};

    virtual dgt_sint32 run() {
        dg_print("\npcp_key_ctrl help\n");
        dg_print(
            "pcp_key_ctrl create -proto tcp|beq -host 192.168.1.20 -port 6688 "
            "-svc demo -user dgadmin\n");
        dg_print(
            "pcp_key_ctrl drop -proto tcp|beq -host 192.168.1.20 -port 6688 "
            "-svc demo -user dgadmin\n");
        dg_print(
            "pcp_key_ctrl open -proto tcp|beq -host 192.168.1.20 -port 6688 "
            "-svc demo -user dgadmin\n");
        dg_print(
            "pcp_key_ctrl close -proto tcp|beq -host 192.168.1.20 -port 6688 "
            "-svc demo -user dgadmin\n");
        dg_print(
            "pcp_key_ctrl chpasswd -proto tcp|beq -host 192.168.1.20 -port "
            "6688 -svc demo -user dgadmin\n");
        dg_print(
            "pcp_key_ctrl export -proto tcp|beq -host 192.168.1.20 -port 6688 "
            "-svc demo -user dgadmin -out file.txt\n");
        dg_print(
            "pcp_key_ctrl import -proto tcp|beq -host 192.168.1.20 -port 6688 "
            "-svc demo -user dgadmin -in file.txt\n");
        dg_print(
            "pcp_key_ctrl set -proto tcp|beq -host 192.168.1.20 -port 6688 "
            "-svc demo -user dgadmin -key_open_mode <auto|manual>\n");
        return 0;
    };
};

class PccCmdCreate : public PccCmd {
   private:
   protected:
   public:
    PccCmdCreate(PccCmdOption& cmd_option) : PccCmd(cmd_option){};
    virtual ~PccCmdCreate(){};

    virtual dgt_sint32 run() {
        dgt_schar passwd[33];
        dgt_schar tmp_pw[33];
        memset(passwd, 0, 33);
        memset(tmp_pw, 0, 33);
        if (UI_UTIL_read_pw_string(passwd, 32, "master key passwd: ", 0)) {
            THROWnR(DgcCipherExcept(
                        -10007,
                        new DgcError(SPOS, "UI_UTIL_read_pw_string failed")),
                    -1);
        }
        if (UI_UTIL_read_pw_string(tmp_pw, 32,
                                   "retype master key passwd: ", 0)) {
            THROWnR(DgcCipherExcept(
                        -10007,
                        new DgcError(SPOS, "UI_UTIL_read_pw_string failed")),
                    -1);
        }
        if (memcmp(passwd, tmp_pw, 32)) {
            THROWnR(DgcCipherExcept(-10007,
                                    new DgcError(SPOS, "password mismatch")),
                    -1);
        }
        dgt_schar sql_text[256];
        dg_sprintf(sql_text, "call pcp_create_key('%s')", passwd);
        if (runSQL(sql_text)) {
            ATHROWnR(DgcError(SPOS, "runSQL failed"), -1);
        }
        return 0;
    };
};

class PccCmdDrop : public PccCmd {
   private:
   protected:
   public:
    PccCmdDrop(PccCmdOption& cmd_option) : PccCmd(cmd_option){};
    virtual ~PccCmdDrop(){};

    virtual dgt_sint32 run() {
        dgt_schar passwd[33];
        memset(passwd, 0, 33);
        if (UI_UTIL_read_pw_string(passwd, 32, "master key passwd: ", 0)) {
            THROWnR(DgcCipherExcept(
                        -10008,
                        new DgcError(SPOS, "UI_UTIL_read_pw_string failed")),
                    -1);
        }
        dgt_schar sql_text[256];
        dg_sprintf(sql_text, "call pcp_drop_key('%s')", passwd);
        if (runSQL(sql_text)) {
            ATHROWnR(DgcError(SPOS, "runSQL failed"), -1);
        }
        return 0;
    };
};

class PccCmdOpen : public PccCmd {
   private:
   protected:
   public:
    PccCmdOpen(PccCmdOption& cmd_option) : PccCmd(cmd_option){};
    virtual ~PccCmdOpen(){};

    virtual dgt_sint32 run() {
        dgt_schar passwd[33];
        memset(passwd, 0, 33);
        if (UI_UTIL_read_pw_string(passwd, 32, "master key passwd: ", 0)) {
            THROWnR(DgcCipherExcept(
                        -10008,
                        new DgcError(SPOS, "UI_UTIL_read_pw_string failed")),
                    -1);
        }
        dgt_schar sql_text[256];
        dg_sprintf(sql_text, "call pcp_open_key('%s')", passwd);
        if (runSQL(sql_text)) {
            ATHROWnR(DgcError(SPOS, "runSQL failed"), -1);
        }
        return 0;
    };
};

class PccCmdClose : public PccCmd {
   private:
   protected:
   public:
    PccCmdClose(PccCmdOption& cmd_option) : PccCmd(cmd_option){};
    virtual ~PccCmdClose(){};

    virtual dgt_sint32 run() {
        dgt_schar passwd[33];
        memset(passwd, 0, 33);
        if (UI_UTIL_read_pw_string(passwd, 32, "master key passwd: ", 0)) {
            THROWnR(DgcCipherExcept(
                        -10009,
                        new DgcError(SPOS, "UI_UTIL_read_pw_string failed")),
                    -1);
        }
        dgt_schar sql_text[256];
        dg_sprintf(sql_text, "call pcp_close_key('%s')", passwd);
        if (runSQL(sql_text)) {
            ATHROWnR(DgcError(SPOS, "runSQL failed"), -1);
        }
        return 0;
    };
};

class PccCmdChPasswd : public PccCmd {
   private:
   protected:
   public:
    PccCmdChPasswd(PccCmdOption& cmd_option) : PccCmd(cmd_option){};
    virtual ~PccCmdChPasswd(){};

    virtual dgt_sint32 run() {
        dgt_schar old_pw[33];
        dgt_schar new_pw[33];
        memset(old_pw, 0, 33);
        memset(new_pw, 0, 33);
        if (UI_UTIL_read_pw_string(old_pw, 32, "old master key passwd: ", 0)) {
            THROWnR(DgcCipherExcept(
                        -10007,
                        new DgcError(SPOS, "UI_UTIL_read_pw_string failed")),
                    -1);
        }
        if (UI_UTIL_read_pw_string(new_pw, 32, "new master key passwd: ", 0)) {
            THROWnR(DgcCipherExcept(
                        -10007,
                        new DgcError(SPOS, "UI_UTIL_read_pw_string failed")),
                    -1);
        }
        dgt_schar sql_text[256];
        dg_sprintf(sql_text, "call pcp_change_wd('%s','%s')", old_pw, new_pw);
        if (runSQL(sql_text)) {
            ATHROWnR(DgcError(SPOS, "runSQL failed"), -1);
        }
        return 0;
    };
};

class PccCmdExport : public PccCmd {
   private:
   protected:
   public:
    PccCmdExport(PccCmdOption& cmd_option) : PccCmd(cmd_option){};
    virtual ~PccCmdExport(){};

    virtual dgt_sint32 run() {
        const dgt_schar* out = CmdOption.optionValue("out");
        if (!out) {
            THROWnR(
                DgcCipherExcept(-10011, new DgcError(SPOS, "out not found")),
                -1);
        }
        DgcFileStream fs(out, O_CREAT | O_WRONLY, 0666);
        if (EXCEPT) {
            ATHROWnR(DgcError(SPOS, "out file open failed"), -1);
        }
        dgt_schar old_pw[33];
        dgt_schar new_pw[33];
        memset(old_pw, 0, 33);
        memset(new_pw, 0, 33);
        if (UI_UTIL_read_pw_string(old_pw, 32, "master key passwd: ", 0)) {
            THROWnR(DgcCipherExcept(
                        -10012,
                        new DgcError(SPOS, "UI_UTIL_read_pw_string failed")),
                    -1);
        }
        if (UI_UTIL_read_pw_string(new_pw, 32,
                                   "export master key passwd: ", 0)) {
            THROWnR(DgcCipherExcept(
                        -10013,
                        new DgcError(SPOS, "UI_UTIL_read_pw_string failed")),
                    -1);
        }
        if (*new_pw) {
            dgt_schar tmp_pw[33];
            memset(tmp_pw, 0, 33);
            if (UI_UTIL_read_pw_string(tmp_pw, 32,
                                       "retype new master key passwd: ", 0)) {
                THROWnR(DgcCipherExcept(
                            -10013, new DgcError(
                                        SPOS, "UI_UTIL_read_pw_string failed")),
                        -1);
            }
            if (memcmp(new_pw, tmp_pw, 32)) {
                THROWnR(DgcCipherExcept(
                            -10007, new DgcError(SPOS, "password mismatch")),
                        -1);
            }
        }
        dgt_schar sql_text[256];
        dg_sprintf(sql_text, "call pcp_export_key('%s','%s')", old_pw, new_pw);
        if (runSQL(sql_text, 0, &fs)) {
            ATHROWnR(DgcError(SPOS, "runSQL failed"), -1);
        }
        return 0;
    };
};

class PccCmdImport : public PccCmd {
   private:
   protected:
   public:
    PccCmdImport(PccCmdOption& cmd_option) : PccCmd(cmd_option){};
    virtual ~PccCmdImport(){};

    virtual dgt_sint32 run() {
        //
        // read from exported keys
        //
        const dgt_schar* in = CmdOption.optionValue("in");
        if (!in) {
            THROWnR(
                DgcCipherExcept(-10014, new DgcError(SPOS, "out not found")),
                -1);
        }
        DgcFileStream fs(in, O_RDONLY);
        if (EXCEPT) {
            ATHROWnR(DgcError(SPOS, "file[%s] open failed", in), -1);
        }
        dgt_schar* key_buf = new dgt_schar[70000];
        PccAutoPtr<dgt_schar> ap(key_buf);
        memset(key_buf, 0, 70000);
        if (fs.recvData((dgt_uint8*)key_buf, 70000) < 0) {
            ATHROWnR(DgcError(SPOS, "recvData failed"), -1);
        }

        //
        // read the master key password and a new one if user wants to change
        // it.
        //
        dgt_schar old_pw[33];
        dgt_schar new_pw[33];
        memset(old_pw, 0, 33);
        memset(new_pw, 0, 33);
        if (UI_UTIL_read_pw_string(old_pw, 32, "master key passwd: ", 0)) {
            THROWnR(DgcCipherExcept(
                        -10012,
                        new DgcError(SPOS, "UI_UTIL_read_pw_string failed")),
                    -1);
        }
        if (UI_UTIL_read_pw_string(new_pw, 32, "new master key passwd: ", 0)) {
            THROWnR(DgcCipherExcept(
                        -10013,
                        new DgcError(SPOS, "UI_UTIL_read_pw_string failed")),
                    -1);
        }
        if (*new_pw) {
            dgt_schar tmp_pw[33];
            memset(tmp_pw, 0, 33);
            if (UI_UTIL_read_pw_string(tmp_pw, 32,
                                       "retype new master key passwd: ", 0)) {
                THROWnR(DgcCipherExcept(
                            -10013, new DgcError(
                                        SPOS, "UI_UTIL_read_pw_string failed")),
                        -1);
            }
            if (memcmp(new_pw, tmp_pw, 32)) {
                THROWnR(DgcCipherExcept(
                            -10007, new DgcError(SPOS, "password mismatch")),
                        -1);
            }
        }

        //
        // build sql text & bind rows
        //
        dgt_schar sql_text[256];
        dg_sprintf(sql_text, "call pcp_import_key(:1,:2,:3)");
        dgt_sint32 buf_len = strlen(key_buf);
        dgt_schar* cp = key_buf;
        DgcMemRows mrows(3);
        mrows.addAttr(DGC_SCHR, 33, "old_pw");
        mrows.addAttr(DGC_SCHR, 33, "new_pw");
        mrows.addAttr(DGC_SCHR, 7000, "keys");
        while (buf_len > 0) {
            mrows.add();
            mrows.next();
            if (cp == key_buf) {
                memcpy(mrows.getColPtr(1), old_pw, 32);
                memcpy(mrows.getColPtr(2), new_pw, 32);
            }
            if (buf_len > 6999) {
                memcpy(mrows.getColPtr(3), cp, 6999);
                cp += 6999;
                buf_len -= 6999;
            } else {
                memcpy(mrows.getColPtr(3), cp, buf_len);
                cp += buf_len;
                buf_len = 0;
            }
        }
        mrows.rewind();
        if (runSQL(sql_text, &mrows)) {
            ATHROWnR(DgcError(SPOS, "runSQL failed"), -1);
        }
        return 0;
    };
};

class PccCmdSet : public PccCmd {
   private:
   protected:
   public:
    PccCmdSet(PccCmdOption& cmd_option) : PccCmd(cmd_option){};
    virtual ~PccCmdSet(){};

    virtual dgt_sint32 run() {
        dgt_schar passwd[33];
        memset(passwd, 0, 33);
        if (UI_UTIL_read_pw_string(passwd, 32, "master key passwd: ", 0)) {
            THROWnR(DgcCipherExcept(
                        -10008,
                        new DgcError(SPOS, "UI_UTIL_read_pw_string failed")),
                    -1);
        }
        dgt_schar sql_text[256];
        const dgt_schar* option;
        if ((option = CmdOption.optionValue("key_open_mode"))) {
            dg_sprintf(sql_text, "call pcp_set_key_open_mode('%s','%s')",
                       passwd, option);
        } else {
            THROWnR(DgcCipherExcept(-10008,
                                    new DgcError(SPOS, "unsupported option")),
                    -1);
        }
        if (runSQL(sql_text)) {
            ATHROWnR(DgcError(SPOS, "runSQL failed"), -1);
        }
        return 0;
    };
};

class PccKeyControl {
   private:
    dgt_schar* Cmd;
    PccCmdOption CmdOption;

   protected:
   public:
    PccKeyControl(dgt_sint32 argc, dgt_schar** argv)
        : Cmd(argv[1]), CmdOption(argc, argv){};
    ~PccKeyControl(){};

    dgt_void runCommand() {
        PccCmd* cmd = 0;
        if (!strcasecmp(Cmd, "help")) {
            cmd = new PccCmdHelp(CmdOption);
        } else if (!strcasecmp(Cmd, "create")) {
            cmd = new PccCmdCreate(CmdOption);
        } else if (!strcasecmp(Cmd, "drop")) {
            cmd = new PccCmdDrop(CmdOption);
        } else if (!strcasecmp(Cmd, "open")) {
            cmd = new PccCmdOpen(CmdOption);
        } else if (!strcasecmp(Cmd, "close")) {
            cmd = new PccCmdClose(CmdOption);
        } else if (!strcasecmp(Cmd, "chpasswd")) {
            cmd = new PccCmdChPasswd(CmdOption);
        } else if (!strcasecmp(Cmd, "export")) {
            cmd = new PccCmdExport(CmdOption);
        } else if (!strcasecmp(Cmd, "import")) {
            cmd = new PccCmdImport(CmdOption);
        } else if (!strcasecmp(Cmd, "set")) {
            cmd = new PccCmdSet(CmdOption);
        } else {
            dg_print("unknown command[%s]\n", Cmd);
            return;
        }
        PccAutoPtr<PccCmd> cmd_ptr(cmd);
        if (cmd->run()) EXCEPT->print();
        delete EXCEPTnC;
    };
};

int main(dgt_sint32 argc, dgt_schar** argv) {
    if (argc < 2) {
        dg_print("usage: pcp_key_ctrl help\n");
        exit(1);
    }
    PccKeyControl key_ctrl(argc, argv);
    key_ctrl.runCommand();
}
