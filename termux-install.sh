#!/usr/bin/env sh
# Installation de Home Cloud (édition lite) sous Termux, sans root.
set -e
echo "==> Paquets nécessaires (compilateur, make, OpenSSL)"
pkg install -y clang make openssl
echo "==> Compilation"
make
echo "==> Installation dans $PREFIX/bin"
make install
echo "==> Assistant de configuration"
exec homecloud-server install
