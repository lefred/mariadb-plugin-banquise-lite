# MariaDB Banquise Lite - mariadb-plugin-banquise-lite

![mariabd-plugin-banquise-lite](logo/banquise_lite_logo.png)

`BANQUISE_LITE` is a MariaDB server plugin that discovers binary
plugins from a Minisign-authenticated HTTPS JSON catalog, verifies each asset's
SHA-256 checksum, copies the
`.so` into MariaDB's configured `plugin_dir`, and loads it with `INSTALL SONAME`.
It is intended for servers that use the Banquise catalog without enrolling in
the Banquise fleet controller.

The catalog is a small, auditable file maintained in a GitHub repository. Each
entry points at another project's release page and at one exact release asset.
See `catalog.example.json` for the schema.

## Build

Add this directory below MariaDB's `plugin/` source directory (or symlink it),
then configure the MariaDB build normally. The build requires the libcurl,
libarchive, and OpenSSL development packages. For example on Debian/Ubuntu:

```sh
sudo apt install libcurl4-openssl-dev libarchive-dev libssl-dev
cmake -S . -B build -DPLUGIN_BANQUISE_LITE=DYNAMIC
cmake --build build --target banquise_lite
```

## Installation

Install `banquise_lite.so` into MariaDB's `plugin_dir`, then bootstrap it:

```sql
INSTALL SONAME 'banquise_lite';

SELECT plugin_name, plugin_type, plugin_library, plugin_description, plugin_author 
FROM information_schema.PLUGINS WHERE plugin_library = 'banquise_lite.so' ORDER BY plugin_name;
+-------------------------+--------------------+------------------+-------------------------------------------------------+---------------+
| plugin_name             | plugin_type        | plugin_library   | plugin_description                                    | plugin_author |
+-------------------------+--------------------+------------------+-------------------------------------------------------+---------------+
| BANQUISE_CATALOG        | INFORMATION SCHEMA | banquise_lite.so | Standalone signed-catalog browser and installer       | lefred        |
| BANQUISE_LITE           | DAEMON             | banquise_lite.so | Standalone Banquise signed-catalog service            | lefred        |
| banquise_lite_install   | FUNCTION           | banquise_lite.so | Download, verify, install and load a catalog plugin   | lefred        |
| banquise_lite_uninstall | FUNCTION           | banquise_lite.so | Unload and remove an installed catalog plugin         | lefred        |
| banquise_lite_update    | FUNCTION           | banquise_lite.so | Safely replace and reload an installed catalog plugin | lefred        |
+-------------------------+--------------------+------------------+-------------------------------------------------------+---------------+
5 rows in set (0.002 sec)
```

Test it:

```sql
SELECT * FROM information_schema.BANQUISE_CATALOG;
```

Before installing the plugin, deploy the catalog publisher's trusted Minisign
public key at `/etc/banquise/catalog.pub`. Key generation, signing,
deployment, and rotation are covered in [SIGNING.md](SIGNING.md). The default catalog is
`https://lefred.be/wp-content/uploads/catalog.json` and is fetched during
plugin initialization, so the information-schema table is populated as soon as
`INSTALL SONAME` returns. To use another catalog, configure
`banquise_lite_catalog_url` before server startup or set it at runtime and refresh:

```sql
SET GLOBAL banquise_lite_catalog_url =
  'https://example.org/mariadb/catalog.json';
SET GLOBAL banquise_lite_refresh = ON;
```

The detached signature is fetched by appending `.minisig` to the configured
URL. For the default URL it must therefore be published as
`catalog.json.minisig`. Configure the read-only trust anchor before server
startup when it is stored elsewhere:

```ini
[mariadb]
banquise_lite_trusted_key_file=/etc/mariadb/banquise/catalog.pub
```

Automatic initialization refresh can be disabled with
`banquise_lite_auto_refresh=OFF`. A network or catalog error does not prevent the
plugin from loading; details are available in `Banquise_lite_message` and a manual
refresh can be attempted later.

Install a compatible entry by catalog name:

```sql
SELECT banquise_lite_install('vmstat');
SHOW STATUS LIKE 'banquise_lite_message';
SHOW PLUGINS;
```

Update an installed plugin to the compatible release currently advertised by
the catalog, or unload it and remove its shared object:

```sql
SELECT banquise_lite_update('vmstat');
SELECT banquise_lite_uninstall('vmstat');
```

## Mutual exclusion with Banquise Agent

`banquise_lite` and `banquise_agent` both register the information-schema
plugin `BANQUISE_CATALOG`. MariaDB therefore rejects loading the second module
while the other is installed and rolls back that `INSTALL SONAME`. This makes
the operating mode mutually exclusive at the plugin-registry level. Uninstall
the active module before switching modes:

```sql
UNINSTALL SONAME 'banquise_agent';
INSTALL SONAME 'banquise_lite';
```

Neither module will install, update, or uninstall the other through its catalog
operations.

Update downloads and verifies the new asset before unloading the current
plugin. It keeps a backup and attempts to restore and reload the previous
version if replacement or loading fails.

`DEPENDENCIES` in the table tells an administrator which runtime libraries or
setup steps the release needs. The catalog `message`, along with the last
refresh/install result, is returned by the `Banquise_lite_message` status
variable.

## Catalog contract

Required string fields are `name`, `repository`, `version`,
`mariadb_version`, `architecture`, `soname`, `download_url`, and `sha256`.
`plugin_types`, `license`, `maturity`, `description`, `dependencies`, `message`,
`archive_type`, and `archive_member` are optional strings. `plugin_types` declares the types
supplied by the shared object, for example `INFORMATION SCHEMA, FUNCTION`.
`license` and `maturity` describe an unloaded catalog artifact, for example
`GPL` and `beta`. `mariadb_version` is a
server-version prefix such as `11.4`, or `any`; `architecture` is `x86_64`,
`aarch64`, `x86`, or `any`. Publish one entry per build combination.

For a direct `.so`, omit `archive_type` and `archive_member`. For a gzip tar
release asset, set `archive_type` to `tar.gz` and `archive_member` to the exact
path of the plugin `.so` inside the archive. The SHA-256 always covers the
downloaded asset (the complete archive), not only the extracted `.so`.

`INFORMATION_SCHEMA.BANQUISE_CATALOG` reports `INSTALLED`, `LOADED`,
`INSTALLED_VERSION`, `PLUGIN_TYPES`, `LICENSE`, `MATURITY`, and `DESCRIPTION`.
`INSTALLED` means that a regular `.so`
exists in `plugin_dir`; `LOADED` reflects MariaDB's live plugin registry. The
installer persists verified version metadata beside the `.so`, so the installed
version remains visible across restarts even when the library is not loaded.
For a loaded library, version, types, license, and maturity come from the live
registry. For an unloaded entry, catalog-declared values are shown.

The catalog `message` is intentionally not exposed as a table column. It is
appended to successful install and update results, allowing publishers to show
dependency or activation instructions at the point of action. `description` is
the discovery-oriented text displayed in the table.

`banquise_lite_update()` compares the installed version with the compatible
catalog version before making a network request. Equal versions return
immediately without downloading or changing the plugin.

The checksum must be the 64-hex-character SHA-256 of the release asset. A
publisher can generate it with:

```sh
sha256sum plugin.so
```

