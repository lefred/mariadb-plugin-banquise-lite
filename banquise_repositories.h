/* Copyright (c) 2026 Frederic Descamps. GPLv2.
   Shared by Banquise Lite and Agent; keep both copies identical. */
#ifndef BANQUISE_REPOSITORIES_H
#define BANQUISE_REPOSITORIES_H
#include <algorithm>
#include <cerrno>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <dirent.h>
#include <fstream>
#include <map>
#include <cstdlib>

struct Banquise_repository
{
  std::string name, url, key;
  bool enabled;

  Banquise_repository(): enabled(true) {}
  Banquise_repository(const std::string &repository_name,
                      const std::string &repository_url,
                      const std::string &repository_key,
                      bool repository_enabled= true):
    name(repository_name), url(repository_url), key(repository_key),
    enabled(repository_enabled) {}
};

static std::string repo_trim(const std::string &s)
{
  const size_t first= s.find_first_not_of(" \t\r\n");
  return first == std::string::npos ? "" :
    s.substr(first, s.find_last_not_of(" \t\r\n") - first + 1);
}

static bool repo_name_valid(const std::string &s)
{
  if (s.empty() || s.size() > 128) return false;
  for (unsigned char c : s)
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
      return false;
  return true;
}

static bool repo_read_cnf(const std::string &path,
                          std::map<std::string, Banquise_repository> *repos,
                          std::string *error, unsigned depth= 0,
                          bool optional= false)
{
  if (depth > 10) { *error= "Repository config include depth exceeded: " + path; return false; }
  struct stat st;
  if (stat(path.c_str(), &st))
  {
    if (optional && errno == ENOENT) return true;
    *error= "Cannot stat repository config: " + path; return false;
  }
  // Match MariaDB's refusal to read world-writable option files.
  if (st.st_mode & S_IWOTH) return true;
  std::ifstream file(path);
  if (!file) { *error= "Cannot read repository config: " + path; return false; }
  std::string line, group;
  while (std::getline(file, line))
  {
    line= repo_trim(line);
    if (line.empty() || line[0] == '#' || line[0] == ';') continue;
    if (line[0] == '!' || line[0] == '?')
    {
      size_t space= line.find_first_of(" \t");
      std::string directive= line.substr(1, space == std::string::npos ? space : space - 1);
      std::string target= space == std::string::npos ? "" : repo_trim(line.substr(space));
      if (directive == "include")
      {
        if (!repo_read_cnf(target, repos, error, depth + 1)) return false;
      }
      else if (directive == "includedir")
      {
        DIR *dir= opendir(target.c_str());
        if (!dir)
        {
          if (line[0] == '?' && errno == EACCES) continue;
          *error= "Cannot read repository config directory: " + target; return false;
        }
        std::vector<std::string> paths;
        while (struct dirent *entry= readdir(dir))
        {
          std::string name= entry->d_name;
          if (name.size() > 4 && name.substr(name.size() - 4) == ".cnf")
            paths.push_back(target + "/" + name);
        }
        closedir(dir);
        std::sort(paths.begin(), paths.end());
        for (const std::string &child : paths)
          if (!repo_read_cnf(child, repos, error, depth + 1)) return false;
      }
      continue;
    }
    if (line[0] == '[')
    {
      size_t end= line.find(']');
      group.clear();
      std::string section= repo_trim(line.substr(1, end == std::string::npos ? end : end - 1));
      if (section.compare(0, 9, "banquise:") == 0)
      {
        group= section.substr(9);
        if (end == std::string::npos || !repo_name_valid(group))
        { *error= "Invalid Banquise repository section in " + path; return false; }
        (*repos)[group].name= group;
      }
      continue;
    }
    if (group.empty()) continue;
    size_t equal= line.find('=');
    std::string key= repo_trim(line.substr(0, equal));
    std::replace(key.begin(), key.end(), '-', '_');
    std::string value= equal == std::string::npos ? "" : repo_trim(line.substr(equal + 1));
    // Strip inline comments outside quotes, then remove matching outer quotes.
    char quote= 0;
    for (size_t i= 0; i < value.size(); ++i)
    {
      if (value[i] == '\\' && i + 1 < value.size()) { ++i; continue; }
      if (quote) { if (value[i] == quote) quote= 0; }
      else if (value[i] == '\'' || value[i] == '"') quote= value[i];
      else if (value[i] == '#') { value.resize(i); break; }
    }
    value= repo_trim(value);
    if (value.size() >= 2 && (value[0] == '\'' || value[0] == '"') && value.back() == value[0])
      value= value.substr(1, value.size() - 2);
    if (key == "catalog_url") (*repos)[group].url= value;
    else if (key == "trusted_key_file") (*repos)[group].key= value;
    else if (key == "enabled")
    {
      if (value == "1" || value == "on" || value == "true" || value == "yes")
        (*repos)[group].enabled= true;
      else if (value == "0" || value == "off" || value == "false" || value == "no")
        (*repos)[group].enabled= false;
      else
      {
        *error= "Invalid enabled value in [banquise:" + group + "]: " + value;
        return false;
      }
    }
    else { *error= "Unknown option in [banquise:" + group + "]: " + key; return false; }
  }
  if (file.bad()) { *error= "Error reading repository config: " + path; return false; }
  return true;
}
// Load all repositories before publishing any entries. The loader must verify
// each repository with its own trust anchor before returning its parsed entries.
template <class Entry, class Loader>
static bool repo_load_entries(const std::vector<Banquise_repository> &repos,
                              std::vector<Entry> *out, Loader loader,
                              std::string *error)
{
  std::vector<Entry> combined;
  for (const Banquise_repository &repo : repos)
  {
    std::vector<Entry> parsed;
    if (!loader(repo, &parsed, error))
    {
      *error= "Repository '" + repo.name + "': " + *error;
      return false;
    }
    for (Entry &entry : parsed)
    {
      entry.catalog= repo.name;
      combined.push_back(std::move(entry));
    }
  }
  out->swap(combined);
  return true;
}

// Return a matching compatible entry, refusing cross-publisher ambiguity.
// Multiple build entries within one repository retain catalog order.
template <class Entry, class Compatible>
static const Entry *repo_select_entry(const std::vector<Entry> &entries,
                                     const std::string &name,
                                     const std::string &catalog,
                                     Compatible compatible, std::string *error)
{
  const Entry *selected= nullptr;
  for (const Entry &entry : entries)
  {
    if (entry.name != name || (!catalog.empty() && entry.catalog != catalog) ||
        !compatible(entry)) continue;
    if (selected && selected->catalog != entry.catalog)
    {
      *error= "Plugin '" + name +
        "' exists in multiple catalogs; specify a repository name";
      return nullptr;
    }
    if (!selected) selected= &entry;
  }
  if (!selected) *error= "No compatible catalog entry named '" + name + "'";
  return selected;
}
#endif
