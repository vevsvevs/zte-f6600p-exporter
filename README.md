# ZTE F6600P Configuration Exporter

Export and inspect your router's configuration, decrypt a saved backup offline, or rebuild a WEB backup from edited XML. Export and restore of rebuilt WEB backups were tested on the **ZTE ZXHN F6600P with Vodafone Spain firmware V9.1.10P5N20 (V14)**. Compatibility with other firmware versions and router models may vary.

## Getting started

Download **`ZTE-F6600P-Export.exe`** for Windows x64 and open a terminal in the download folder. The executable runs without a Python installation. Windows SmartScreen may show a warning because the executable is unsigned. [Releases](../../releases/latest)

To run from source, use Python 3.11 or later.

```bash
python -m pip install requests cryptography psutil
python zte_f6600p_export.py
```

For the Windows commands below, replace `.\ZTE-F6600P-Export.exe` with `python zte_f6600p_export.py` when running from source.

## Export from the router

Connect to the router's local network and run the tool without arguments.

```text
.\ZTE-F6600P-Export.exe
```

Enter the router's private IPv4 address and the web interface username and password printed on the router's label. Press Enter to accept `192.168.1.1` and `user` if they match your setup. The tool downloads and decrypts the WEB configuration, then tries to collect the internal configuration over Telnet. It uses an existing Telnet service if available and asks for its credentials. Otherwise, it attempts to open temporary Factory Telnet access.

The tool prints the path to the new `zte_export_...` folder in the working directory.

| File | Contents |
| --- | --- |
| `webcfg_dbase.xml` | Decrypted WEB configuration. Use this XML as the starting point for rebuilding a WEB backup. |
| `webcfg_creds.txt` | Readable credentials report, which can include administrator, Wi-Fi, PPPoE, and SIP details. |
| `telnet_show2.txt` | Output of `setmac show2`, which lists internal device parameters such as `VENDORID`, `GPONSN`, `GPONPWD`, and `MAC1`. |
| `telnet_dbase.xml` | Decrypted configuration database read over Telnet. It normally contains the same configuration as `webcfg_dbase.xml`, with a minor difference in a table header. |
| `telnet_creds.txt` | Connection details the tool can save if you keep Telnet open or the close request fails. |

If Telnet collection fails, you can still use the WEB files from a successful WEB export. By default, the tool requests closure of confirmed Telnet access. Check that access is disabled after you finish.

## Decrypt an existing backup offline

Pass the file to the tool. This mode works without a router connection.

```text
.\ZTE-F6600P-Export.exe .\configurationBackup.cfg
```

- **WEB backup**. Enter the backup password. The tool saves `webcfg_dbase.xml` and `webcfg_creds.txt` in a new `zte_export_...` folder.
- **Native Type 6 database**. Pass the database file and enter the router's GPON serial and MAC1, if available from its Telnet readout. The tool saves the decrypted database as `telnet_dbase.xml` in a new export folder.

## Rebuild a WEB backup

> **Warning.** Uploading a modified configuration can overwrite settings, interrupt Internet or voice service, or lock you out of the router. Before restoring, save a known-good backup and its password and make sure you have a recovery method. Restore at your own risk.

Save a backup copy of `webcfg_dbase.xml` from the target router, then edit the original file in the export folder, keeping its XML encoding. Pass either the edited XML file or the export folder.

```text
.\ZTE-F6600P-Export.exe .\export-directory\webcfg_dbase.xml
.\ZTE-F6600P-Export.exe .\export-directory
```

Choose a password for the new backup, then enter the router's GPON serial. Press Enter to accept the serial suggested from `telnet_show2.txt` in the same folder, if available. Otherwise, enter the full serial, for example `ZTEG12345678`.

The tool checks XML syntax and saves a new `*_repacked.cfg` beside the XML. It refuses to overwrite an existing backup. To apply the file, use the router's WEB restore page and the password you chose during packing.

## Responsible use and affiliation

Use the tool only on equipment you own or have permission to administer. Keep decrypted exports, credentials reports, and Telnet files private. They can contain passwords and subscriber or device information.

This is an independent, unofficial project. ZTE and Vodafone are unaffiliated with the project and provide no endorsement or support for it. Product and brand names are used to identify the router and firmware.

## Credits, AI disclosure, and license

The source code and this documentation were **generated with assistance from OpenAI ChatGPT**, under the direction of the project maintainer. Core features were tested on the ZTE F6600P described above; other configurations have not been fully validated.

Factory Mode / Telnet functionality is adapted from the work of [langit7/zte-modem-tools-gui](https://github.com/langit7/zte-modem-tools-gui), [langit7/zte_modem_tools](https://github.com/langit7/zte_modem_tools), and [douniwan5788/zte_modem_tools](https://github.com/douniwan5788/zte_modem_tools). Thanks to their contributors.

The WEB packer uses the ZTE container and compression conventions documented by [mkst/zte-config-utility](https://github.com/mkst/zte-config-utility).

Licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0-only)**. See [LICENSE](LICENSE).
