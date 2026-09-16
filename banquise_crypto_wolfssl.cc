/* Copyright (c) 2026 Frederic Descamps
   GPLv2 -- MariaDB plugin repository and verified installer. */

#include "banquise_crypto.h"

#include <wolfssl/wolfcrypt/blake2.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <cstring>
#include <vector>

static std::vector<std::string> text_lines(const std::string &text)
{
  std::vector<std::string> lines;
  size_t begin= 0;
  while (begin < text.size())
  {
    size_t end= text.find('\n', begin);
    if (end == std::string::npos) end= text.size();
    std::string line= text.substr(begin, end - begin);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    lines.push_back(line);
    begin= end + 1;
  }
  while (!lines.empty() && lines.back().empty()) lines.pop_back();
  return lines;
}

static bool decode_base64(const std::string &input, size_t expected,
                          std::vector<unsigned char> *output)
{
  if (input.empty() || input.size() % 4) return false;
  output->resize(input.size() / 4 * 3);
  word32 output_len= (word32) output->size();
  if (Base64_Decode(reinterpret_cast<const byte *>(input.data()),
                    (word32) input.size(), output->data(), &output_len) != 0)
    return false;
  if ((size_t) output_len != expected) return false;
  output->resize(output_len);
  return true;
}

static bool ed25519_verify(const unsigned char public_key[32],
                           const unsigned char signature[64],
                           const unsigned char *message, size_t message_len)
{
  ed25519_key key;
  int verified= 0;
  if (wc_ed25519_init(&key) != 0)
    return false;
  if (wc_ed25519_import_public(public_key, 32, &key) != 0)
  {
    wc_ed25519_free(&key);
    return false;
  }
  int result= wc_ed25519_verify_msg(signature, 64, message,
                                    (word32) message_len, &verified, &key);
  wc_ed25519_free(&key);
  return result == 0 && verified == 1;
}

static bool blake2b_digest(const std::string &message, unsigned char digest[64])
{
  Blake2b context;
  return wc_InitBlake2b(&context, 64) == 0 &&
    wc_Blake2bUpdate(&context,
                     reinterpret_cast<const byte *>(message.data()),
                     (word32) message.size()) == 0 &&
    wc_Blake2bFinal(&context, digest, 64) == 0;
}

#include "banquise_crypto_minisign.inc"
