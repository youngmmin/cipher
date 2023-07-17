which m4 > /dev/null 2>&1
[[ $? -ne 0 ]] && echo "m4 not found" && exit 1

which aclocal > /dev/null 2>&1
[[ $? -ne 0 ]] && echo "aclocal not found" && exit 1

which automake > /dev/null 2>&1
[[ $? -ne 0 ]] && echo "automake not found" && exit 1

which autoconf > /dev/null 2>&1
[[ $? -ne 0 ]] && echo "autoconf not found" && exit 1

which libtool > /dev/null 2>&1
[[ $? -ne 0 ]] && echo "libtool not found" && exit 1


aclocal
[[ -f configure ]] && rm configure
autoconf

ln -sf Makefile Makefile.inc

echo "run ./configure to generate Makefile"
echo ""
echo "example:"
echo "    ./configure PETRA_ROOT_DIR=/path/to/src PETRA_TOOLS_DIR=/public/tools"
echo "    ./make"



