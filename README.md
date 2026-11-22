# ZTE F6600P Configuration Exporter

A small command-line tool for exporting and decrypting configuration data from supported ZTE routers and rebuilding encrypted WEB backups from exported XML. The export modes were developed and tested with a **ZTE ZXHN F6600P running Vodafone Spain firmware V9.1.10P5N20 (V14)**. Restoring a rebuilt backup on that firmware is pending hardware verification.

## Modes

### Online mode

Connects to the router, downloads and decrypts its web configuration, and creates a readable credentials report. It then uses temporary Factory Telnet (or an existing Telnet session) to collect GPON information and decrypt the internal configuration database. At the end, you can choose to **leave Telnet enabled**; by default, the tool attempts to close it. If Telnet is unavailable, the web configuration export may still succeed.

### Offline decryption

Decrypts a previously saved ZTE Type 6 web backup or internal configuration database **without connecting to the router**. Web backups also produce a credentials report.

### Offline WEB backup packing

Pass a WEB configuration XML file as the sole argument. The tool builds a ZTE F6600P Type 6 container, writes `<name>_repacked.cfg` next to the XML, and prints the newly generated backup password. Use that password for WEB restore. If the output already exists, choose a different XML filename or move the previous output.

Start with a copy of `webcfg_dbase.xml` from the target router. Preserve the original XML encoding when editing. The packer checks XML syntax and reports the line and column of a syntax error. A comma after an attribute's closing quote is invalid, while a comma inside a quoted value or in element text is valid XML. The packer preserves the original bytes. Firmware-specific checks happen during restore.

The packer generates the documented ZTE container header from scratch. Compatibility with any additional header metadata required by the Vodafone V14 WEB importer still needs to be verified on the router.

## Download and usage

Download **`ZTE-F6600P-Export.exe`** from [Releases](../../releases/latest) (Windows x64). No Python installation is required for this executable.

Open Windows Terminal in the folder containing the downloaded file and run:

```powershell
.\ZTE-F6600P-Export.exe
```

For offline decryption:

```powershell
.\ZTE-F6600P-Export.exe configurationBackup.cfg
```

The export modes prompt for required credentials and save their files in newly created local folders. If you keep temporary Telnet enabled in online mode, reboot the router afterward and verify that access is no longer available.

### Run from source

Requires Python 3.11+:

```bash
python -m pip install requests cryptography psutil
python zte_f6600p_export.py
```

For offline decryption, pass the backup filename as the first argument. To try packing from this branch, run from source:

```bash
python zte_f6600p_export.py edited.xml
```

This writes `edited_repacked.cfg` in the same folder. For example, `home.v2.xml` becomes `home.v2_repacked.cfg`. You can also pass an export directory to pack its `webcfg_dbase.xml`.

During packing, the tool asks for the GPON serial to write into the backup's Board S/N header. It looks for `telnet_show2.txt` in the supplied directory or, for an XML argument, beside the XML. Press Enter to accept the serial shown in brackets, or type a different one. If the file is missing or contains no usable serial, enter the full serial manually (for example, `ZTEG12345678`). Copy the password printed in the terminal for the WEB restore.

## Verify a rebuilt backup

1. Download a backup through the WEB interface and keep it and its password for recovery.
2. Edit a copy of the WEB XML and change a reversible setting, such as the guest Wi-Fi name while managing the router over Ethernet. Pack the edited XML with the command above.
3. Restore `edited_repacked.cfg` through the WEB interface using the password printed by the tool. Check that the setting changed.

For an optional byte-for-byte comparison, export the reference backup from the router using the same password printed by the tool. Compare the two files with `fc.exe /b` on Windows or `cmp` on Linux and macOS. Equality requires the same XML bytes, compression output, and header metadata.

## Security and limitations

- **Use only on equipment you own or administer with permission.**
- Output files may contain sensitive credentials, including administrator, PPPoE, SIP, and Wi-Fi passwords. **Never upload your configuration exports, HAR files, or credentials to a public repository.**
- The executable is currently unsigned; Windows may show a SmartScreen warning. Inspect the source and download only from a release you trust.
- This is an independent, unofficial project, not affiliated with ZTE or Vodafone. Use at your own risk.

## Credits, AI disclosure, and license

The source code and this documentation were **generated with assistance from OpenAI ChatGPT**, under the direction of the project maintainer. Core features were tested on the ZTE F6600P described above; other configurations have not been fully validated.

Factory Mode / Telnet functionality is adapted from the work of [langit7/zte-modem-tools-gui](https://github.com/langit7/zte-modem-tools-gui), [langit7/zte_modem_tools](https://github.com/langit7/zte_modem_tools), and [douniwan5788/zte_modem_tools](https://github.com/douniwan5788/zte_modem_tools). Thanks to their contributors.

The WEB packer uses the ZTE container and compression conventions documented by [mkst/zte-config-utility](https://github.com/mkst/zte-config-utility).

Licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0-only)**. See [LICENSE](LICENSE).
