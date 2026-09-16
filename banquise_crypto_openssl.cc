/* Copyright (c) 2026 Frederic Descamps
   GPLv2 -- MariaDB plugin repository and verified installer. */

#include "banquise_crypto.h"

#include <openssl/evp.h>
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
  int n= EVP_DecodeBlock(output->data(),
                         reinterpret_cast<const unsigned char *>(input.data()),
                         (int) input.size());
  if (n < 0) return false;
  if (!input.empty() && input.back() == '=') --n;
  if (input.size() > 1 && input[input.size() - 2] == '=') --n;
  if ((size_t) n != expected) return false;
  output->resize((size_t) n);
  return true;
}

static bool ed25519_verify(const unsigned char public_key[32],
                           const unsigned char signature[64],
                           const unsigned char *message, size_t message_len)
{
  EVP_PKEY *key= EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                             public_key, 32);
  EVP_MD_CTX *ctx= key ? EVP_MD_CTX_new() : NULL;
  bool valid= ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
    EVP_DigestVerify(ctx, signature, 64, message, message_len) == 1;
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(key);
  return valid;
}

static bool blake2b_digest(const std::string &message, unsigned char digest[64])
{
  unsigned int digest_len= 0;
  return EVP_Digest(message.data(), message.size(), digest, &digest_len,
                    EVP_blake2b512(), NULL) == 1 && digest_len == 64;
}

#include "banquise_crypto_minisign.inc"
