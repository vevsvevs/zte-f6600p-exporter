# ZTE F6600P Configuration Exporter

A small command-line tool for exporting and decrypting configuration data from supported ZTE routers. Developed and tested with a **ZTE ZXHN F6600P running Vodafone Spain firmware V9.1.10P5N20 (V14)**. Compatibility beyond the tested device is not guaranteed.

## Modes

### Online mode

Connects to the router, downloads and decrypts its web configuration, and creates a readable credentials report. It then uses temporary Factory Telnet (or an existing Telnet session) to collect GPON information and decrypt the internal configuration database. At the end, you can choose to **leave Telnet enabled**; by default, the tool attempts to close it. If Telnet is unavailable, the web configuration export may still succeed.

### Offline mode

Decrypts a previously saved ZTE Type 6 web backup or internal configuration database **without connecting to the router**. Web backups also produce a credentials report.

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

The tool prompts for required credentials and saves exported files in a newly created local folder. If you keep temporary Telnet enabled in online mode, reboot the router afterward and verify that access is no longer available.

### Run from source

Requires Python 3.11+:

```bash
python -m pip install requests cryptography psutil
python zte_f6600p_export.py
```

For offline mode, pass the configuration filename as the first argument.

## Security and limitations

- **Use only on equipment you own or administer with permission.**
- Output files may contain sensitive credentials, including administrator, PPPoE, SIP, and Wi-Fi passwords. **Never upload your configuration exports, HAR files, or credentials to a public repository.**
- The executable is currently unsigned; Windows may show a SmartScreen warning. Inspect the source and download only from a release you trust.
- This is an independent, unofficial project, not affiliated with ZTE or Vodafone. Use at your own risk.

## Credits, AI disclosure, and license

The source code and this documentation were **generated with assistance from OpenAI ChatGPT**, under the direction of the project maintainer. Core features were tested on the ZTE F6600P described above; other configurations have not been fully validated.

Factory Mode / Telnet functionality is adapted from the work of [langit7/zte-modem-tools-gui](https://github.com/langit7/zte-modem-tools-gui), [langit7/zte_modem_tools](https://github.com/langit7/zte_modem_tools), and [douniwan5788/zte_modem_tools](https://github.com/douniwan5788/zte_modem_tools). Thanks to their contributors.

Licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0-only)**. See [LICENSE](LICENSE).
