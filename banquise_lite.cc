/* Copyright (c) 2026 Frederic Descamps
   GPLv2 -- MariaDB plugin repository and verified installer. */

#define MYSQL_SERVER 1
#include <my_global.h>
#include <my_sys.h>
#include <mysql/plugin.h>
#include <mysql/service_json.h>
#include <mysql/service_my_crypt.h>
#include <mysql/service_sql.h>
#include <sql_acl.h>
#include <sql_class.h>
#include <sql_i_s.h>
#include <sql_plugin.h>
#include <mysql/plugin_function.h>

#include <curl/curl.h>
#include <archive.h>
#include <archive_entry.h>
#include <openssl/evp.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define BANQUISE_LITE_VERSION 0x0001
#define MAX_CATALOG_BYTES (4U * 1024U * 1024U)
#define MAX_PLUGIN_BYTES (256U * 1024U * 1024U)
#define MAX_SIGNATURE_BYTES (16U * 1024U)
#define MAX_PUBLIC_KEY_BYTES (4U * 1024U)

extern char server_version[];

struct Repo_entry
{
  std::string name, repository, version, mariadb_version, architecture;
  std::string soname, download_url, sha256, archive_type, archive_member;
  std::string plugin_types, license, maturity, description, dependencies, message;
};

static std::mutex repo_lock;
static std::mutex operation_lock;
static std::vector<Repo_entry> entries;
static char *catalog_url;
static char *trusted_key_file;
static my_bool refresh_command;
static my_bool auto_refresh= 1;
static char status_message[2048]= "Catalog has not been refreshed";
static ulong repo_connect_timeout= 10;
static ulong repo_transfer_timeout= 120;

static void set_message(const std::string &s)
{
  std::lock_guard<std::mutex> guard(repo_lock);
  strmake(status_message, s.c_str(), sizeof(status_message) - 1);
}

struct Download
{
  std::string data;
  size_t limit;
  bool too_large;
  Download(size_t n): limit(n), too_large(false) {}
};

static size_t curl_write(char *ptr, size_t size, size_t nmemb, void *opaque)
{
  Download *d= static_cast<Download *>(opaque);
  size_t n= size * nmemb;
  if (n > d->limit - std::min(d->limit, d->data.size()))
  {
    d->too_large= true;
    return 0;
  }
  d->data.append(ptr, n);
  return n;
}

static bool https_url(const std::string &url)
{
  return url.size() > 8 && url.compare(0, 8, "https://") == 0;
}

static bool fetch(const std::string &url, size_t limit, std::string *out,
                  std::string *error)
{
  if (!https_url(url))
  {
    *error= "Only https:// URLs are allowed";
    return false;
  }
  CURL *curl= curl_easy_init();
  if (!curl)
  {
    *error= "Cannot initialize libcurl";
    return false;
  }
  Download d(limit);
  char curl_error[CURL_ERROR_SIZE]= {0};
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
  curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
  curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long) repo_connect_timeout);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long) repo_transfer_timeout);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  /* GitHub and some TLS middleboxes occasionally terminate HTTP/2 streams
     without a clean TLS close_notify. HTTP/1.1 plus bounded retries avoids
     turning that transient transport condition into an installation failure. */
  curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "mariadb-banquise-lite/0.1");
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_error);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &d);
  CURLcode rc= CURLE_OK;
  long response= 0;
  for (int attempt= 0; attempt < 3; ++attempt)
  {
    d.data.clear();
    d.too_large= false;
    curl_error[0]= 0;
    response= 0;
    rc= curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
    bool transient= rc == CURLE_RECV_ERROR || rc == CURLE_PARTIAL_FILE ||
      rc == CURLE_SSL_CONNECT_ERROR || rc == CURLE_GOT_NOTHING ||
      rc == CURLE_HTTP2 || response == 429 || response >= 500;
    if (!transient || d.too_large || attempt == 2) break;
  }
  curl_easy_cleanup(curl);
  if (rc != CURLE_OK || response < 200 || response >= 300)
  {
    if (d.too_large)
      *error= "Download exceeds configured safety limit";
    else if (rc != CURLE_OK)
      *error= curl_error[0] ? curl_error : curl_easy_strerror(rc);
    else
      *error= "HTTP " + std::to_string(response) + " returned for " + url;
    return false;
  }
  out->swap(d.data);
  return true;
}

static bool read_trusted_key(std::string *contents, std::string *error)
{
  if (!trusted_key_file || !trusted_key_file[0])
  {
    *error= "Set banquise_lite_trusted_key_file to a local Minisign public key";
    return false;
  }
  int fd= open(trusted_key_file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
  {
    *error= std::string("Cannot open trusted Minisign key: ") + strerror(errno);
    return false;
  }
  struct stat st;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
      st.st_size > MAX_PUBLIC_KEY_BYTES)
  {
    close(fd);
    *error= "Trusted Minisign key must be a non-empty regular file under 4 KiB";
    return false;
  }
  if (st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)))
  {
    close(fd);
    *error= "Trusted Minisign key must be root-owned and not group- or world-writable";
    return false;
  }
  contents->clear();
  contents->resize((size_t) st.st_size);
  size_t done= 0;
  while (done < contents->size())
  {
    ssize_t n= read(fd, &(*contents)[done], contents->size() - done);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0)
    {
      close(fd);
      *error= "Cannot read the complete trusted Minisign key";
      return false;
    }
    done+= (size_t) n;
  }
  close(fd);
  return true;
}

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

static bool verify_minisign(const std::string &message,
                            const std::string &signature_text,
                            const std::string &public_key_text,
                            std::string *error)
{
  const std::string trusted_prefix= "trusted comment: ";
  std::vector<std::string> key_lines= text_lines(public_key_text);
  std::vector<std::string> sig_lines= text_lines(signature_text);
  if (key_lines.size() != 2 || sig_lines.size() != 4 ||
      key_lines[0].compare(0, 18, "untrusted comment:") != 0 ||
      sig_lines[0].compare(0, 18, "untrusted comment:") != 0 ||
      sig_lines[2].compare(0, trusted_prefix.size(), trusted_prefix) != 0)
  {
    *error= "Malformed Minisign public key or signature file";
    return false;
  }
  std::vector<unsigned char> key_packet, sig_packet, global_signature;
  if (!decode_base64(key_lines[1], 42, &key_packet) ||
      !decode_base64(sig_lines[1], 74, &sig_packet) ||
      !decode_base64(sig_lines[3], 64, &global_signature))
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
  unsigned int digest_len= 0;
  if (EVP_Digest(message.data(), message.size(), digest, &digest_len,
                 EVP_blake2b512(), NULL) != 1 || digest_len != sizeof(digest) ||
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
    *error= "Minisign trusted-comment signature is invalid";
    return false;
  }
  return true;
}

static bool json_string_field(const char *object, int object_len,
                              const char *key, std::string *out,
                              bool required, std::string *error)
{
  const char *value= NULL;
  int len= 0;
  enum json_types type= json_get_object_key(object, object + object_len, key,
                                             &value, &len);
  if (type == JSV_NOTHING && !required)
  {
    out->clear();
    return true;
  }
  if (type != JSV_STRING)
  {
    *error= std::string("Catalog field '") + key + "' must be a string";
    return false;
  }
  std::vector<char> decoded((size_t) len + 1);
  int n= json_unescape_json(value, value + len, decoded.data(),
                            decoded.data() + decoded.size() - 1);
  if (n < 0)
  {
    *error= std::string("Invalid JSON escape in '") + key + "'";
    return false;
  }
  out->assign(decoded.data(), (size_t) n);
  return true;
}

static bool safe_name(const std::string &s)
{
  if (s.empty() || s.size() > 128) return false;
  for (unsigned char c : s)
    if (!(std::isalnum(c) || c == '_' || c == '-')) return false;
  return true;
}

static bool safe_soname(const std::string &s)
{
  if (s.size() < 4 || s.size() > 128 || s.substr(s.size() - 3) != ".so")
    return false;
  for (unsigned char c : s)
    if (!(std::isalnum(c) || c == '_' || c == '-' || c == '.')) return false;
  return s.find("..") == std::string::npos;
}

static bool valid_sha256(const std::string &s)
{
  if (s.size() != 64) return false;
  return std::all_of(s.begin(), s.end(), [](unsigned char c) {
    return std::isxdigit(c) != 0;
  });
}

static bool parse_catalog(const std::string &json,
                          std::vector<Repo_entry> *parsed,
                          std::string *error)
{
  const char *plugins= NULL;
  int plugins_len= 0;
  const char *root_value= NULL;
  int root_len= 0;
  if (json_type(json.data(), json.data() + json.size(), &root_value, &root_len) != JSV_OBJECT ||
      json_get_object_key(json.data(), json.data() + json.size(), "plugins",
                          &plugins, &plugins_len) != JSV_ARRAY)
  {
    *error= "Catalog root must be an object containing a plugins array";
    return false;
  }
  for (int i= 0;; ++i)
  {
    const char *obj= NULL;
    int len= 0;
    enum json_types type= json_get_array_item(plugins, plugins + plugins_len, i,
                                               &obj, &len);
    if (type == JSV_NOTHING) break;
    if (type != JSV_OBJECT)
    {
      *error= "Every plugins item must be an object";
      return false;
    }
    Repo_entry e;
    if (!json_string_field(obj, len, "name", &e.name, true, error) ||
        !json_string_field(obj, len, "repository", &e.repository, true, error) ||
        !json_string_field(obj, len, "version", &e.version, true, error) ||
        !json_string_field(obj, len, "mariadb_version", &e.mariadb_version, true, error) ||
        !json_string_field(obj, len, "architecture", &e.architecture, true, error) ||
        !json_string_field(obj, len, "soname", &e.soname, true, error) ||
        !json_string_field(obj, len, "download_url", &e.download_url, true, error) ||
        !json_string_field(obj, len, "sha256", &e.sha256, true, error) ||
        !json_string_field(obj, len, "archive_type", &e.archive_type, false, error) ||
        !json_string_field(obj, len, "archive_member", &e.archive_member, false, error) ||
        !json_string_field(obj, len, "plugin_types", &e.plugin_types, false, error) ||
        !json_string_field(obj, len, "license", &e.license, false, error) ||
        !json_string_field(obj, len, "maturity", &e.maturity, false, error) ||
        !json_string_field(obj, len, "description", &e.description, false, error) ||
        !json_string_field(obj, len, "dependencies", &e.dependencies, false, error) ||
        !json_string_field(obj, len, "message", &e.message, false, error))
      return false;
    if (!safe_name(e.name) || !safe_soname(e.soname) ||
        !https_url(e.repository) || !https_url(e.download_url) ||
        !valid_sha256(e.sha256) ||
        (!e.archive_type.empty() && e.archive_type != "tar.gz") ||
        ((e.archive_type == "tar.gz") != !e.archive_member.empty()))
    {
      *error= "Unsafe name, soname, URL, or SHA-256 in catalog entry " + e.name;
      return false;
    }
    std::transform(e.sha256.begin(), e.sha256.end(), e.sha256.begin(), ::tolower);
    parsed->push_back(e);
  }
  return true;
}

static bool safe_archive_member(const std::string &path)
{
  if (path.empty() || path.size() > 1024 || path[0] == '/') return false;
  size_t start= 0;
  while (start <= path.size())
  {
    size_t end= path.find('/', start);
    std::string component= path.substr(start, end - start);
    if (component.empty() || component == "." || component == "..") return false;
    if (end == std::string::npos) break;
    start= end + 1;
  }
  return true;
}

static bool plugin_payload(const Repo_entry &entry, const std::string &asset,
                           std::string *payload, std::string *error)
{
  if (entry.archive_type.empty())
  {
    *payload= asset;
    return true;
  }
  if (entry.archive_type != "tar.gz" ||
      !safe_archive_member(entry.archive_member))
  {
    *error= "Invalid archive type or member path";
    return false;
  }

  struct archive *reader= archive_read_new();
  archive_read_support_filter_gzip(reader);
  archive_read_support_format_tar(reader);
  if (archive_read_open_memory(reader, asset.data(), asset.size()) != ARCHIVE_OK)
  {
    *error= std::string("Cannot open tar.gz asset: ") + archive_error_string(reader);
    archive_read_free(reader);
    return false;
  }

  bool found= false, failed= false;
  struct archive_entry *item;
  int archive_rc;
  while ((archive_rc= archive_read_next_header(reader, &item)) == ARCHIVE_OK)
  {
    const char *pathname= archive_entry_pathname(item);
    if (!pathname || entry.archive_member != pathname)
    {
      archive_read_data_skip(reader);
      continue;
    }
    if (found || archive_entry_filetype(item) != AE_IFREG ||
        archive_entry_symlink(item) || archive_entry_hardlink(item))
    {
      *error= "Archive member is duplicated, linked, or not a regular file";
      failed= true;
      break;
    }
    found= true;
    char buffer[8 * 1024];
    for (;;)
    {
      la_ssize_t n= archive_read_data(reader, buffer, sizeof(buffer));
      if (n == 0) break;
      if (n < 0 || (size_t) n > MAX_PLUGIN_BYTES -
          std::min((size_t) MAX_PLUGIN_BYTES, payload->size()))
      {
        *error= n < 0 ? std::string("Cannot extract plugin: ") +
          archive_error_string(reader) : "Extracted plugin exceeds safety limit";
        failed= true;
        break;
      }
      payload->append(buffer, (size_t) n);
    }
    if (failed) break;
  }
  if (!failed && archive_rc != ARCHIVE_EOF)
  {
    *error= std::string("Invalid or truncated archive: ") +
            archive_error_string(reader);
    failed= true;
  }
  archive_read_free(reader);
  if (failed) return false;
  if (!found)
  {
    *error= "Declared archive_member was not found";
    return false;
  }
  if (payload->empty())
  {
    *error= "Extracted plugin is empty";
    return false;
  }
  return true;
}

static bool refresh(std::string *error)
{
  if (!catalog_url || !catalog_url[0])
  {
    *error= "Set banquise_lite_catalog_url to an HTTPS catalog";
    return false;
  }
  std::string body, signature, public_key;
  if (!fetch(catalog_url, MAX_CATALOG_BYTES, &body, error)) return false;
  if (!fetch(std::string(catalog_url) + ".minisig", MAX_SIGNATURE_BYTES,
             &signature, error))
  {
    *error= "Cannot download catalog signature: " + *error;
    return false;
  }
  if (!read_trusted_key(&public_key, error) ||
      !verify_minisign(body, signature, public_key, error)) return false;
  std::vector<Repo_entry> parsed;
  if (!parse_catalog(body, &parsed, error)) return false;
  {
    std::lock_guard<std::mutex> guard(repo_lock);
    entries.swap(parsed);
  }
  return true;
}

static std::string local_architecture()
{
#if defined(__x86_64__) || defined(_M_X64)
  return "x86_64";
#elif defined(__aarch64__)
  return "aarch64";
#elif defined(__i386__)
  return "x86";
#else
  return "unknown";
#endif
}

static bool compatible(const Repo_entry &e)
{
  std::string version(server_version);
  return (e.architecture == "any" || e.architecture == local_architecture()) &&
         (e.mariadb_version == "any" ||
          version.compare(0, e.mariadb_version.size(), e.mariadb_version) == 0);
}

static std::string sha256_hex(const std::string &data)
{
  unsigned char digest[32];
  my_sha256(digest, data.data(), data.size());
  static const char hex[]= "0123456789abcdef";
  std::string result(64, '0');
  for (size_t i= 0; i < sizeof(digest); ++i)
  {
    result[i * 2]= hex[digest[i] >> 4];
    result[i * 2 + 1]= hex[digest[i] & 15];
  }
  return result;
}

static bool write_plugin(const Repo_entry &e, const std::string &data,
                         std::string *error)
{
  std::string final_path= std::string(opt_plugin_dir) + FN_LIBCHAR + e.soname;
  std::string temp_path= final_path + ".banquise-lite.tmp";
  int fd= open(temp_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0755);
  if (fd < 0)
  {
    *error= "Cannot create temporary plugin file: " + std::string(strerror(errno));
    return false;
  }
  size_t done= 0;
  bool ok= true;
  while (done < data.size())
  {
    ssize_t n= write(fd, data.data() + done, data.size() - done);
    if (n <= 0) { ok= false; break; }
    done+= (size_t) n;
  }
  if (ok && fsync(fd)) ok= false;
  if (close(fd)) ok= false;
  /* link(2) publishes atomically and, unlike rename(2), never overwrites an
     administrator-managed plugin that appeared after our initial checks. */
  if (!ok || link(temp_path.c_str(), final_path.c_str()))
  {
    int saved_errno= errno;
    unlink(temp_path.c_str());
    *error= "Cannot install plugin file: " + std::string(strerror(saved_errno));
    return false;
  }
  unlink(temp_path.c_str());
  return true;
}

static bool sql_soname(const char *command, const std::string &soname,
                       std::string *error)
{
  MYSQL *mysql= mysql_init(NULL);
  if (!mysql || !mysql_real_connect_local(mysql))
  {
    *error= "Local SQL connection could not be opened";
    if (mysql) mysql_close(mysql);
    return false;
  }
  std::string sql= std::string(command) + " SONAME '" + soname + "'";
  bool failed= mysql_real_query(mysql, sql.data(), sql.size()) != 0;
  if (failed) *error= std::string(command) + " SONAME failed: " +
                      mysql_error(mysql);
  mysql_close(mysql);
  return !failed;
}

static bool catalog_entry(const std::string &name, Repo_entry *selected,
                          std::string *error)
{
  std::lock_guard<std::mutex> guard(repo_lock);
  for (const Repo_entry &e : entries)
    if (e.name == name && compatible(e))
    {
      *selected= e;
      if (e.soname == "banquise_lite.so" || e.soname == "banquise_agent.so")
      {
        *error= "Banquise Lite cannot manage itself or banquise_agent";
        return false;
      }
      return true;
    }
  *error= "No compatible catalog entry named '" + name + "'";
  return false;
}

static std::string metadata_path(const std::string &soname)
{
  return std::string(opt_plugin_dir) + FN_LIBCHAR + soname +
         ".banquise-lite.meta";
}

static bool read_installed_version(const std::string &soname,
                                   std::string *version)
{
  int fd= open(metadata_path(soname).c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return false;
  char data[512];
  ssize_t length= read(fd, data, sizeof(data));
  close(fd);
  if (length <= 0 || length == (ssize_t) sizeof(data)) return false;
  const char *newline= static_cast<const char *>(memchr(data, '\n', length));
  size_t version_length= newline ? (size_t) (newline - data) : (size_t) length;
  if (!version_length || version_length > 255) return false;
  version->assign(data, version_length);
  return true;
}

static bool write_installed_metadata(const Repo_entry &entry,
                                     std::string *error)
{
  std::string final_path= metadata_path(entry.soname);
  std::string temp_path= final_path + ".tmp";
  std::string content= entry.version + "\n" + entry.sha256 + "\n";
  int fd= open(temp_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
  if (fd < 0)
  {
    *error= "Cannot create installed-version metadata: " +
            std::string(strerror(errno));
    return false;
  }
  size_t done= 0;
  bool ok= true;
  while (done < content.size())
  {
    ssize_t written= write(fd, content.data() + done, content.size() - done);
    if (written <= 0) { ok= false; break; }
    done+= (size_t) written;
  }
  if (ok && fsync(fd)) ok= false;
  if (close(fd)) ok= false;
  if (!ok || rename(temp_path.c_str(), final_path.c_str()))
  {
    int saved_errno= errno;
    unlink(temp_path.c_str());
    *error= "Cannot publish installed-version metadata: " +
            std::string(strerror(saved_errno));
    return false;
  }
  return true;
}

struct Loaded_version_context
{
  const std::string &soname;
  std::string version;
  bool loaded= false;
  explicit Loaded_version_context(const std::string &name): soname(name) {}
};

static my_bool find_loaded_version(THD *, plugin_ref ref, void *opaque)
{
  st_plugin_int *internal= plugin_ref_to_int(ref);
  Loaded_version_context *context=
    static_cast<Loaded_version_context *>(opaque);
  if (!internal || !internal->plugin_dl || !internal->plugin ||
      context->soname != std::string(internal->plugin_dl->dl.str,
                                     internal->plugin_dl->dl.length))
    return FALSE;
  context->loaded= true;
  if (context->version.empty() && internal->plugin->version_info)
    context->version= internal->plugin->version_info;
  return FALSE;
}

static bool loaded_version(const std::string &soname, std::string *version)
{
  Loaded_version_context context(soname);
  if (plugin_foreach(current_thd, find_loaded_version, MYSQL_ANY_PLUGIN,
                     &context))
    return false;
  if (context.loaded) *version= context.version;
  return context.loaded;
}

static bool install(const std::string &name, std::string *error,
                    std::string *notice)
{
  std::lock_guard<std::mutex> operation_guard(operation_lock);
  Repo_entry selected;
  if (!catalog_entry(name, &selected, error)) return false;

  std::string path= std::string(opt_plugin_dir) + FN_LIBCHAR + selected.soname;
  struct stat st;
  if (!stat(path.c_str(), &st))
  {
    if (!S_ISREG(st.st_mode))
    {
      *error= "Plugin path already exists but does not resolve to a regular file: " +
              path;
      return false;
    }
    std::string installed_version, runtime_version;
    bool is_loaded= loaded_version(selected.soname, &runtime_version);
    bool trusted= read_installed_version(selected.soname, &installed_version);
    if (trusted && installed_version == selected.version)
    {
      if (is_loaded)
      {
        *notice= selected.name + " " + installed_version +
                 " is already installed and loaded";
        return true;
      }
      if (!sql_soname("INSTALL", selected.soname, error)) return false;
      *notice= "Loaded already-installed " + selected.name + " " +
               installed_version;
      return true;
    }
    *error= "Plugin path already exists without matching trusted repository "
            "metadata: " + path +
            ". Remove or relocate it before repository installation, or load "
            "the unmanaged file with INSTALL SONAME manually";
    return false;
  }
  if (errno != ENOENT)
  {
    *error= "Cannot inspect plugin path: " + std::string(strerror(errno));
    return false;
  }

  std::string data;
  if (!fetch(selected.download_url, MAX_PLUGIN_BYTES, &data, error)) return false;
  if (sha256_hex(data) != selected.sha256)
  {
    *error= "SHA-256 mismatch; downloaded file was not installed";
    return false;
  }
  std::string payload;
  if (!plugin_payload(selected, data, &payload, error)) return false;
  if (!write_plugin(selected, payload, error)) return false;
  if (!write_installed_metadata(selected, error))
  {
    unlink(path.c_str());
    return false;
  }
  if (!sql_soname("INSTALL", selected.soname, error)) return false;
  *notice= "Installed and loaded " + selected.name + " " + selected.version;
  if (!selected.dependencies.empty()) *notice+= ". Dependencies: " + selected.dependencies;
  if (!selected.message.empty()) *notice+= ". " + selected.message;
  return true;
}

static bool uninstall(const std::string &name, std::string *error,
                      std::string *notice)
{
  std::lock_guard<std::mutex> operation_guard(operation_lock);
  Repo_entry selected;
  if (!catalog_entry(name, &selected, error)) return false;
  std::string ignored_version;
  if (loaded_version(selected.soname, &ignored_version) &&
      !sql_soname("UNINSTALL", selected.soname, error)) return false;
  std::string path= std::string(opt_plugin_dir) + FN_LIBCHAR + selected.soname;
  if (unlink(path.c_str()))
  {
    *error= "Plugin unloaded but its file could not be removed: " +
            std::string(strerror(errno));
    return false;
  }
  if (unlink(metadata_path(selected.soname).c_str()) && errno != ENOENT)
  {
    *error= "Plugin removed but installed-version metadata could not be removed: " +
            std::string(strerror(errno));
    return false;
  }
  *notice= "Removed " + selected.name + " (" +
           selected.soname + ")";
  return true;
}

static bool update(const std::string &name, std::string *error,
                   std::string *notice)
{
  std::lock_guard<std::mutex> operation_guard(operation_lock);
  Repo_entry selected;
  if (!catalog_entry(name, &selected, error)) return false;

  std::string final_path= std::string(opt_plugin_dir) + FN_LIBCHAR + selected.soname;
  std::string backup_path= final_path + ".banquise-lite.backup";
  struct stat st;
  if (lstat(final_path.c_str(), &st) || !S_ISREG(st.st_mode))
  {
    *error= "Installed plugin file is missing or is not a regular file";
    return false;
  }
  std::string installed_version;
  std::string runtime_version;
  bool was_loaded= loaded_version(selected.soname, &runtime_version);
  read_installed_version(selected.soname, &installed_version);
  if (installed_version.empty())
    installed_version= runtime_version;
  if (installed_version == selected.version)
  {
    *notice= selected.name + " " + selected.version +
             " is already installed; no download or update was needed";
    return true;
  }

  /* Fetch and authenticate the replacement while the old plugin is live. */
  std::string data;
  if (!fetch(selected.download_url, MAX_PLUGIN_BYTES, &data, error)) return false;
  if (sha256_hex(data) != selected.sha256)
  {
    *error= "SHA-256 mismatch; the installed plugin was not changed";
    return false;
  }
  std::string payload;
  if (!plugin_payload(selected, data, &payload, error)) return false;

  if (!lstat(backup_path.c_str(), &st) || errno != ENOENT)
  {
    *error= "A previous update backup exists; manual recovery is required";
    return false;
  }
  if (was_loaded && !sql_soname("UNINSTALL", selected.soname, error)) return false;
  if (rename(final_path.c_str(), backup_path.c_str()))
  {
    std::string ignored;
    if (was_loaded) sql_soname("INSTALL", selected.soname, &ignored);
    *error= "Plugin unloaded but its file could not be backed up: " +
            std::string(strerror(errno));
    return false;
  }

  std::string install_error;
  bool updated= write_plugin(selected, payload, &install_error) &&
                (!was_loaded || sql_soname("INSTALL", selected.soname,
                                           &install_error));
  if (!updated)
  {
    unlink(final_path.c_str());
    bool restored= rename(backup_path.c_str(), final_path.c_str()) == 0;
    std::string reload_error;
    bool reloaded= restored && (!was_loaded ||
      sql_soname("INSTALL", selected.soname, &reload_error));
    *error= "Update failed: " + install_error;
    *error+= reloaded ? ". Previous version restored and loaded" :
      ". WARNING: previous version could not be restored and loaded: " +
      reload_error;
    return false;
  }
  if (!write_installed_metadata(selected, error))
  {
    unlink(metadata_path(selected.soname).c_str());
    return false;
  }
  if (unlink(backup_path.c_str()))
  {
    *error= "Plugin updated, but backup file could not be removed: " +
            std::string(strerror(errno));
    return false;
  }
  *notice= "Updated " + selected.name + " to " + selected.version;
  *notice+= was_loaded ? " and loaded it" : " (it remains unloaded)";
  if (!selected.dependencies.empty()) *notice+= ". Dependencies: " + selected.dependencies;
  if (!selected.message.empty()) *notice+= ". " + selected.message;
  return true;
}

static int check_refresh(MYSQL_THD opaque_thd, st_mysql_sys_var *, void *save,
                         st_mysql_value *value)
{
  *static_cast<my_bool *>(save)= 1;
  THD *thd= static_cast<THD *>(opaque_thd);
  if (check_global_access(thd, SUPER_ACL, true)) return 1;
  long long requested= 0;
  if (value->val_int(value, &requested) || !requested) return 0;
  std::string error;
  if (!refresh(&error)) { set_message("Refresh failed: " + error); return 1; }
  set_message("Catalog refreshed successfully");
  return 0;
}

static MYSQL_SYSVAR_STR(catalog_url, catalog_url,
  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,
  "HTTPS URL of the signed-checksum plugin catalog", NULL, NULL,
  "https://lefred.be/wp-content/uploads/catalog.json");
static MYSQL_SYSVAR_STR(trusted_key_file, trusted_key_file,
  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY | PLUGIN_VAR_MEMALLOC,
  "Local Minisign public key used to authenticate catalogs", NULL, NULL,
  "/etc/mariadb/banquise/catalog.pub");
static MYSQL_SYSVAR_BOOL(auto_refresh, auto_refresh, PLUGIN_VAR_RQCMDARG,
  "Refresh the catalog when the plugin is initialized", NULL, NULL, 1);
static MYSQL_SYSVAR_ULONG(connect_timeout, repo_connect_timeout, PLUGIN_VAR_RQCMDARG,
  "HTTPS connect timeout in seconds", NULL, NULL, 10, 1, 300, 1);
static MYSQL_SYSVAR_ULONG(transfer_timeout, repo_transfer_timeout, PLUGIN_VAR_RQCMDARG,
  "HTTPS transfer timeout in seconds", NULL, NULL, 120, 1, 3600, 1);
static MYSQL_SYSVAR_BOOL(refresh, refresh_command, PLUGIN_VAR_OPCMDARG,
  "Set to ON to refresh the catalog", check_refresh, NULL, 0);
static st_mysql_sys_var *repo_vars[]= {
  MYSQL_SYSVAR(catalog_url), MYSQL_SYSVAR(trusted_key_file),
  MYSQL_SYSVAR(auto_refresh), MYSQL_SYSVAR(connect_timeout),
  MYSQL_SYSVAR(transfer_timeout), MYSQL_SYSVAR(refresh), NULL
};

static st_mysql_show_var repo_status[]= {
  {"banquise_lite_message", status_message, SHOW_CHAR},
  {NULL, NULL, SHOW_UNDEF}
};

struct Runtime_plugin_info
{
  std::vector<std::string> versions;
  std::vector<std::string> types;
  std::vector<std::string> licenses;
  std::vector<std::string> maturities;
};

typedef std::unordered_map<std::string, Runtime_plugin_info> Runtime_plugin_map;

static void add_unique(std::vector<std::string> *items, const std::string &item)
{
  if (std::find(items->begin(), items->end(), item) == items->end())
    items->push_back(item);
}

static my_bool collect_runtime_plugin(THD *, plugin_ref ref, void *opaque)
{
  st_plugin_int *internal= plugin_ref_to_int(ref);
  if (!internal || !internal->plugin_dl || !internal->plugin) return FALSE;
  st_maria_plugin *declaration= internal->plugin;
  Runtime_plugin_info &info=
    (*static_cast<Runtime_plugin_map *>(opaque))[
      std::string(internal->plugin_dl->dl.str, internal->plugin_dl->dl.length)];

  if (declaration->version_info && declaration->version_info[0])
    add_unique(&info.versions, declaration->version_info);
  else
  {
    char version[32];
    my_snprintf(version, sizeof(version), "%u.%u",
                declaration->version >> 8, declaration->version & 0xff);
    add_unique(&info.versions, version);
  }
  if (declaration->type >= 0 && declaration->type < MYSQL_MAX_PLUGIN_TYPE_NUM)
    add_unique(&info.types, std::string(plugin_type_names[declaration->type].str,
                                        plugin_type_names[declaration->type].length));
  switch (declaration->license)
  {
  case PLUGIN_LICENSE_GPL:
    add_unique(&info.licenses, PLUGIN_LICENSE_GPL_STRING); break;
  case PLUGIN_LICENSE_BSD:
    add_unique(&info.licenses, PLUGIN_LICENSE_BSD_STRING); break;
  default:
    add_unique(&info.licenses, PLUGIN_LICENSE_PROPRIETARY_STRING); break;
  }
  if (declaration->maturity <= MariaDB_PLUGIN_MATURITY_STABLE)
    add_unique(&info.maturities, plugin_maturity_names[declaration->maturity]);
  else
    add_unique(&info.maturities, "unknown");
  return FALSE;
}

static std::string join(const std::vector<std::string> &items)
{
  std::string result;
  for (const std::string &item : items)
  {
    if (!result.empty()) result+= ", ";
    result+= item;
  }
  return result;
}

namespace Show {
static ST_FIELD_INFO fields[]= {
  Column("NAME", Varchar(128), NOT_NULL),
  Column("REPOSITORY", Varchar(1024), NOT_NULL),
  Column("PLUGIN_VERSION", Varchar(64), NOT_NULL),
  Column("INSTALLED", Varchar(3), NOT_NULL),
  Column("LOADED", Varchar(3), NOT_NULL),
  Column("INSTALLED_VERSION", Varchar(255), NOT_NULL),
  Column("PLUGIN_TYPES", Varchar(1024), NOT_NULL),
  Column("LICENSE", Varchar(255), NOT_NULL),
  Column("MATURITY", Varchar(255), NOT_NULL),
  Column("DESCRIPTION", Varchar(2048), NOT_NULL),
  Column("MARIADB_VERSION", Varchar(64), NOT_NULL),
  Column("ARCHITECTURE", Varchar(64), NOT_NULL),
  Column("SONAME", Varchar(128), NOT_NULL),
  Column("DOWNLOAD_URL", Varchar(2048), NOT_NULL),
  Column("SHA256", Varchar(64), NOT_NULL),
  Column("ARCHIVE_TYPE", Varchar(16), NOT_NULL),
  Column("ARCHIVE_MEMBER", Varchar(1024), NOT_NULL),
  Column("DEPENDENCIES", Varchar(1024), NOT_NULL),
  Column("COMPATIBLE", Varchar(3), NOT_NULL),
  CEnd()
};
}

static int fill_table(THD *thd, TABLE_LIST *tables, COND *)
{
  TABLE *table= tables->table;
  std::lock_guard<std::mutex> operation_guard(operation_lock);
  Runtime_plugin_map runtime_plugins;
  if (plugin_foreach(thd, collect_runtime_plugin, MYSQL_ANY_PLUGIN,
                     &runtime_plugins))
    return 1;
  std::lock_guard<std::mutex> guard(repo_lock);
  for (const Repo_entry &e : entries)
  {
    restore_record(table, s->default_values);
    Runtime_plugin_map::const_iterator loaded= runtime_plugins.find(e.soname);
    bool is_loaded= loaded != runtime_plugins.end();
    std::string path= std::string(opt_plugin_dir) + FN_LIBCHAR + e.soname;
    struct stat st;
    /* stat(), intentionally, counts a symlink resolving to a regular plugin.
       MariaDB can load it and link(2) installation would see the path as busy. */
    bool is_installed= !stat(path.c_str(), &st) && S_ISREG(st.st_mode);
    std::string installed_version;
    if (is_installed)
      read_installed_version(e.soname, &installed_version);
    if (installed_version.empty() && is_loaded)
      installed_version= join(loaded->second.versions);
    std::string plugin_types= is_loaded ? join(loaded->second.types) : e.plugin_types;
    std::string license= is_loaded ? join(loaded->second.licenses) : e.license;
    std::string maturity= is_loaded ? join(loaded->second.maturities) : e.maturity;
    const std::string values[]= { e.name, e.repository, e.version,
      is_installed ? "YES" : "NO", is_loaded ? "YES" : "NO",
      installed_version, plugin_types, license, maturity, e.description,
      e.mariadb_version, e.architecture, e.soname, e.download_url, e.sha256,
      e.archive_type, e.archive_member, e.dependencies,
      compatible(e) ? "YES" : "NO" };
    for (uint i= 0; i < array_elements(values); ++i)
      table->field[i]->store(values[i].data(), values[i].size(), system_charset_info);
    if (schema_table_store_record(thd, table)) return 1;
  }
  return 0;
}

static int schema_init(void *p)
{
  ST_SCHEMA_TABLE *schema= static_cast<ST_SCHEMA_TABLE *>(p);
  schema->fields_info= Show::fields;
  schema->fill_table= fill_table;
  return 0;
}

static int lite_init(void *)
{
  if (curl_global_init(CURL_GLOBAL_DEFAULT)) return 1;
  if (auto_refresh)
  {
    std::string error;
    if (!refresh(&error))
      set_message("Initial catalog refresh failed: " + error);
    else
    {
      size_t count;
      {
        std::lock_guard<std::mutex> guard(repo_lock);
        count= entries.size();
      }
      set_message("Initial catalog refresh succeeded: " +
                  std::to_string(count) + " entries loaded");
    }
  }
  else
    set_message("Ready; automatic catalog refresh is disabled");
  return 0;
}

static int lite_deinit(void *)
{
  curl_global_cleanup();
  return 0;
}

static st_mysql_information_schema descriptor=
  { MYSQL_INFORMATION_SCHEMA_INTERFACE_VERSION };
static st_mysql_daemon daemon_descriptor=
  { MYSQL_DAEMON_INTERFACE_VERSION };

enum Repo_action { ACTION_INSTALL, ACTION_UNINSTALL, ACTION_UPDATE };

class Item_func_banquise_lite_action : public Item_str_func
{
  Repo_action action;
  bool executed= false;
  bool succeeded= false;
  std::string result;
public:
  Item_func_banquise_lite_action(THD *thd, Item *arg, Repo_action action_arg):
    Item_str_func(thd, arg), action(action_arg) {}

  LEX_CSTRING func_name_cstring() const override
  {
    static LEX_CSTRING names[]= {
      { STRING_WITH_LEN("banquise_lite_install") },
      { STRING_WITH_LEN("banquise_lite_uninstall") },
      { STRING_WITH_LEN("banquise_lite_update") }
    };
    return names[action];
  }

  bool fix_length_and_dec(THD *) override
  {
    collation.set(system_charset_info);
    max_length= sizeof(status_message) * system_charset_info->mbmaxlen;
    set_maybe_null();
    return false;
  }

  String *val_str(String *to) override
  {
    DBUG_ASSERT(fixed());
    if (!executed)
    {
      executed= true;
      if (check_global_access(current_thd, SUPER_ACL, true))
      {
        null_value= true;
        return NULL;
      }

      StringBuffer<256> arg_buffer;
      String *arg= args[0]->val_str(&arg_buffer);
      if (!arg || args[0]->null_value)
        result= "Plugin name must not be NULL";
      else
      {
        std::string name(arg->ptr(), arg->length()), error, notice;
        if (!safe_name(name))
          result= "Invalid plugin name";
        else
        {
          switch (action)
          {
          case ACTION_INSTALL: succeeded= install(name, &error, &notice); break;
          case ACTION_UNINSTALL: succeeded= uninstall(name, &error, &notice); break;
          case ACTION_UPDATE: succeeded= update(name, &error, &notice); break;
          }
          result= succeeded ? notice : error;
        }
      }

      if (!succeeded)
      {
        static const char *verbs[]= { "Install", "Uninstall", "Update" };
        set_message(std::string(verbs[action]) + " failed: " + result);
        my_printf_error(ER_UNKNOWN_ERROR, "BANQUISE_LITE: %s", MYF(0),
                        result.c_str());
        null_value= true;
        return NULL;
      }
      set_message(result);
    }

    if (!succeeded || to->copy(result.data(), result.size(), system_charset_info))
    {
      null_value= true;
      return NULL;
    }
    null_value= false;
    return to;
  }

  bool const_item() const override { return false; }

  Item *shallow_copy(THD *thd) const override
  { return get_item_copy<Item_func_banquise_lite_action>(thd, this); }
};

template <Repo_action action> class Create_func_banquise_lite_action :
  public Create_func_arg1
{
public:
  Item *create_1_arg(THD *thd, Item *arg) override
  { return new (thd->mem_root) Item_func_banquise_lite_action(thd, arg, action); }
  static Create_func_banquise_lite_action singleton;
};

template <Repo_action action>
Create_func_banquise_lite_action<action>
  Create_func_banquise_lite_action<action>::singleton;
static Plugin_function install_function_descriptor(
  &Create_func_banquise_lite_action<ACTION_INSTALL>::singleton);
static Plugin_function uninstall_function_descriptor(
  &Create_func_banquise_lite_action<ACTION_UNINSTALL>::singleton);
static Plugin_function update_function_descriptor(
  &Create_func_banquise_lite_action<ACTION_UPDATE>::singleton);

#define BANQUISE_LITE_ENTRY_VARS(TYPE, DESC, NAME, TEXT, INIT, DEINIT, STATUS, VARS) \
 { TYPE, DESC, NAME, "lefred", TEXT, PLUGIN_LICENSE_GPL, INIT, DEINIT, \
   BANQUISE_LITE_VERSION, STATUS, VARS, "0.1.0", \
   MariaDB_PLUGIN_MATURITY_EXPERIMENTAL }
#define BANQUISE_LITE_ENTRY(TYPE, DESC, NAME, TEXT) \
 BANQUISE_LITE_ENTRY_VARS(TYPE, DESC, NAME, TEXT, NULL, NULL, NULL, NULL)

maria_declare_plugin(banquise_lite)
  BANQUISE_LITE_ENTRY_VARS(MYSQL_INFORMATION_SCHEMA_PLUGIN, &descriptor,
                           "BANQUISE_CATALOG",
                           "Standalone signed-catalog browser and installer",
                           schema_init, NULL, NULL, NULL),
  BANQUISE_LITE_ENTRY_VARS(MYSQL_DAEMON_PLUGIN, &daemon_descriptor,
                           "BANQUISE_LITE", "Standalone Banquise signed-catalog service",
                           lite_init, lite_deinit, repo_status, repo_vars),
  BANQUISE_LITE_ENTRY(MariaDB_FUNCTION_PLUGIN, &install_function_descriptor,
                      "banquise_lite_install", "Download, verify, install and load a catalog plugin"),
  BANQUISE_LITE_ENTRY(MariaDB_FUNCTION_PLUGIN, &uninstall_function_descriptor,
                      "banquise_lite_uninstall", "Unload and remove an installed catalog plugin"),
  BANQUISE_LITE_ENTRY(MariaDB_FUNCTION_PLUGIN, &update_function_descriptor,
                      "banquise_lite_update", "Safely replace and reload an installed catalog plugin")
maria_declare_plugin_end;

#undef BANQUISE_LITE_ENTRY
#undef BANQUISE_LITE_ENTRY_VARS
