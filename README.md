# ZTE F6600P Configuration Exporter

A small command-line tool for exporting and decrypting configuration data from supported ZTE routers and rebuilding encrypted WEB backups from exported XML. The export modes were developed and tested with a **ZTE ZXHN F6600P running Vodafone Spain firmware V9.1.10P5N20 (V14)**. Restoring a rebuilt backup on that firmware is pending hardware verification.

## Modes

### Online mode

Connects to the router, downloads and decrypts its web configuration, and creates a readable credentials report. It then uses temporary Factory Telnet (or an existing Telnet session) to collect GPON information and decrypt the internal configuration database. At the end, you can choose to **leave Telnet enabled**; by default, the tool attempts to close it. If Telnet is unavailable, the web configuration export may still succeed.

### Offline decryption

Decrypts a previously saved ZTE Type 6 web backup or internal configuration database **without connecting to the router**. Web backups also produce a credentials report.

### Offline WEB backup packing

Pass a WEB configuration XML file as the sole argument. The tool asks for an original Type 6 WEB backup from the target router and that backup's password. It reuses the router's backup header, then compresses and encrypts the XML using that password. The tool decrypts its output and checks it against the input bytes before writing `<name>.repacked.cfg` next to the XML. If that output already exists, choose a different XML filename or move the previous output.

Start with a copy of the WEB XML exported from the same router and firmware. Use a template exported with the same WEB account level. If you obtained `webcfg_dbase.xml` in online mode, use a fresh WEB backup saved in the browser as the template. Online mode exports the full WEB XML as administrator. The Telnet XML and the router's native Type 6 database are separate formats for this workflow.

The tool requires well-formed XML without a DTD and compares the element order, table and field names, row counts, and attribute names with the template's decrypted XML. Preserve the original XML encoding when editing. The tool accepts changes to setting values. Firmware-specific constraints and linked settings require verification on the device.

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

Enter the path to the original `.cfg` and its backup password at the prompts. When the firmware asks for the backup password during WEB restore, enter that same password.

## Verify a rebuilt backup

1. In the WEB interface, download an original Type 6 backup (`before.cfg`) and keep it for recovery. Choose a reversible setting that leaves management access intact, such as the guest Wi-Fi network name while you are connected by Ethernet.
2. Change that setting in the WEB interface, then download `after.cfg` with the same backup password. Decrypt both files with the script. Compare their `webcfg_dbase.xml` files to identify the exact field and any other changes made by the firmware.
3. Copy the XML from `before.cfg` to `edited.xml` and apply the same setting change. Pack it using `before.cfg` as the template. Decrypt `edited.repacked.cfg` and compare its XML with the one from `after.cfg`, for example using `git diff --no-index` with the two XML paths. The changed field should match. Account for any additional changes that the router made in step 2. Compressed and encrypted files can differ byte for byte even when their XML is equivalent.
4. Revert the test setting through the WEB interface so that it is back at its original value. Then restore `edited.repacked.cfg` through the WEB interface and verify that the new value takes effect. Keep `before.cfg` and its password at hand to restore the original settings.

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
