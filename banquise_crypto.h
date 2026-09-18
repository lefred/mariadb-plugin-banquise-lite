/* Copyright (c) 2026 Frederic Descamps
   GPLv2 -- MariaDB plugin repository and verified installer. */

#ifndef BANQUISE_CRYPTO_H
#define BANQUISE_CRYPTO_H

#include <string>
#include <vector>

std::vector<std::string> banquise_text_lines(const std::string &text);

bool banquise_decode_base64(const std::string &input, size_t expected,
                            std::vector<unsigned char> *output);

bool banquise_verify_minisign(const std::string &message,
                              const std::string &signature_text,
                              const std::string &public_key_text,
                              std::string *error);

#endif
