bool banquise_verify_minisign(const std::string &message,
                                     const std::string &signature_text,
                                     const std::string &public_key_text,
                                     std::string *error)
{
  const std::string trusted_prefix= "trusted comment: ";
  std::vector<std::string> key_lines= banquise_text_lines(public_key_text);
  std::vector<std::string> sig_lines= banquise_text_lines(signature_text);
  if (key_lines.size() != 2 || sig_lines.size() != 4 ||
      key_lines[0].compare(0, 18, "untrusted comment:") != 0 ||
      sig_lines[0].compare(0, 18, "untrusted comment:") != 0 ||
      sig_lines[2].compare(0, trusted_prefix.size(), trusted_prefix) != 0)
  {
    *error= "Malformed Minisign public key or signature file";
    return false;
  }
  std::vector<unsigned char> key_packet, sig_packet, global_signature;
  if (!banquise_decode_base64(key_lines[1], 42, &key_packet) ||
      !banquise_decode_base64(sig_lines[1], 74, &sig_packet) ||
      !banquise_decode_base64(sig_lines[3], 64, &global_signature))
  {
    *error= "Invalid base64 or packet length in Minisign data";
    return false;
  }
  if (key_packet[0] != 'E' || key_packet[1] != 'd' ||
      sig_packet[0] != 'E' || sig_packet[1] != 'D')
  {
    *error= "Unsupported Minisign algorithm (an ED prehashed signature is required)";
    return false;
  }
  if (memcmp(&key_packet[2], &sig_packet[2], 8))
  {
    *error= "Minisign signature key ID does not match the trusted key";
    return false;
  }
  unsigned char digest[64];
  if (!blake2b_digest(message, digest) ||
      !ed25519_verify(&key_packet[10], &sig_packet[10], digest, sizeof(digest)))
  {
    *error= "Catalog Minisign signature is invalid";
    return false;
  }
  std::string trusted_comment= sig_lines[2].substr(trusted_prefix.size());
  std::vector<unsigned char> global_message(64 + trusted_comment.size());
  memcpy(global_message.data(), &sig_packet[10], 64);
  memcpy(global_message.data() + 64, trusted_comment.data(), trusted_comment.size());
  if (!ed25519_verify(&key_packet[10], global_signature.data(),
                      global_message.data(), global_message.size()))
  {
    *error= "Catalog trusted-comment signature is invalid";
    return false;
  }
  return true;
}
