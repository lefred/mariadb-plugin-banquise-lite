/* Copyright (c) 2026 Frederic Descamps
   GPLv2 -- MariaDB plugin repository and verified installer. */

#ifndef BANQUISE_CRYPTO_H
#define BANQUISE_CRYPTO_H

#include <string>

bool banquise_verify_minisign(const std::string &message,
                              const std::string &signature_text,
                              const std::string &public_key_text,
                              std::string *error);

#endif
