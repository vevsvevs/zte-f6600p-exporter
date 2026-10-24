#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""ZTE F6600P configuration export and optional factory Telnet reader.
The script never reboots the router or changes its saved configuration.

Factory-mode protocol adaptation references:
https://github.com/langit7/zte-modem-tools-gui (AGPL-3.0)
https://github.com/langit7/zte_modem_tools
"""
from __future__ import annotations
import argparse
import datetime
import base64
import codecs
import hashlib
import html
import ipaddress
import json
import os
import secrets
import socket
import re
import struct
import sys
import time
import zlib
from pathlib import Path
from urllib.parse import quote
from xml.etree import ElementTree as ET
import requests
import psutil
from urllib3.filepost import encode_multipart_formdata
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

MAGIC = bytes.fromhex('999999994444444455555555aaaaaaaa')
ZTE_IV = b'ZTE%FN$GponNJ025'
PAYLOAD_MAGIC = 0x01020304
SIG_MAGIC = 0x04030201
TIMEOUT = (5, 25)
DEFAULT_PROFILE = 'vodafone_v14'


# Adaptation point for other ZTE models and firmware versions.
# Add another named profile here and select it with --profile.
# The login/backup endpoints are HTTP paths relative to the router's address.
# backup_page and wan_status are ZTE menu tags rather than HTTP paths.
WEB_PROFILES = {
    'vodafone_v14': {
        'login_entry': '/?_type=loginData&_tag=login_entry',         # Login state and submission.
        'login_token': '/?_type=loginData&_tag=login_token',         # Challenge/nonce for login.
        'logout': '/?_type=loginData&_tag=logout_entry',             # End the WEB session.
        'backup_page': 'usrCfgMgr',                                 # Backup page (menuView tag).
        'prepare_backup': '/?_type=menuData&_tag=vdf_download_prevent_ctl.lua',  # Authorize export.
        'download_backup': '/?_type=menuData&_tag=vdf_do_download_usercfg.lua',  # Download .cfg.
        'wan_status': 'wan_internetstatus_lua.lua',                  # WAN status (menuData tag).
        'factory_handshake': '/webFac',                             # Factory-mode authentication.
        'factory_commands': '/webFacEntry',                         # Factory-mode commands.
    },
}


class Progress:
    """Compact, readable progress updates without logging secrets."""

    @staticmethod
    def title(text: str) -> None:
        print('\n' + '=' * 54, flush=True)
        print('  ' + text, flush=True)
        print('=' * 54, flush=True)

    @staticmethod
    def stage(number: int, title: str) -> None:
        print(f'\n[{number}] {title}', flush=True)

    @staticmethod
    def action(text: str) -> None:
        print(f'    - {text}', flush=True)

    @staticmethod
    def ok(text: str) -> None:
        print(f'    + {text}', flush=True)

    @staticmethod
    def warn(text: str) -> None:
        print(f'    ! {text}', file=sys.stderr, flush=True)

    @staticmethod
    def finish(out: Path, result: str = 'COMPLETE') -> None:
        print('\n' + '-' * 54, flush=True)
        print(f'  EXPORT {result}', flush=True)
        print(f'  Files: {out}', flush=True)
        print('-' * 54, flush=True)


def safe_write(path: Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(contents)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def unpack_zte_chunks(inner: bytes, max_size: int = 32_000_000) -> bytes:
    """Unpack the shared ZTE payload format and check CRC/length."""
    if len(inner) < 72:
        raise ValueError('Decrypted ZTE payload is too short')
    header = struct.unpack_from('>15I', inner)
    if header[:2] != (PAYLOAD_MAGIC, 0):
        raise ValueError('Wrong key or unsupported ZTE encryption variant')
    if header[2] > max_size:
        raise ValueError('Decompressed configuration exceeds size limit')

    pos, crc, output = 60, 0, bytearray()
    for _ in range(1024):
        if pos + 12 > len(inner):
            raise ValueError('Truncated compressed ZTE chunk')
        n_plain, n_z, cont = struct.unpack_from('>III', inner, pos)
        pos += 12
        if (n_plain > max_size - len(output) or n_z > len(inner) - pos):
            raise ValueError('Invalid ZTE chunk length')
        compressed = inner[pos:pos+n_z]
        pos += n_z
        try:
            dec = zlib.decompressobj()
            plain = dec.decompress(compressed, n_plain+1)
            if dec.unconsumed_tail or not dec.eof or dec.unused_data:
                raise ValueError('Invalid compressed chunk framing')
            plain += dec.flush()
        except zlib.error as exc:
            raise ValueError('Invalid compressed configuration') from exc
        if len(plain) != n_plain:
            raise ValueError('ZTE chunk size mismatch')
        output += plain
        crc = zlib.crc32(compressed, crc)
        if not cont:
            break
    else:
        raise ValueError('Too many compressed ZTE chunks')

    if pos != len(inner) or crc != header[5] or len(output) != header[2]:
        raise ValueError('ZTE payload checksum or length mismatch')
    if ET.fromstring(output).tag != 'DB':
        raise ValueError('Payload is not a ZTE XML database')
    return bytes(output)


def decrypt_backup(blob: bytes, backup_password: str) -> bytes:
    i = blob.find(MAGIC)
    if i < 0:
        raise ValueError('Type 6 ZTE container not found')
    data = memoryview(blob)[i:]
    offset = 128
    sigmagic, _unused, siglen = struct.unpack_from('>III', data, offset)
    if sigmagic != SIG_MAGIC or not (1 <= siglen <= 128):
        raise ValueError('Unknown signature block')
    offset += 12
    signature = bytes(data[offset:offset+siglen]).decode('ascii')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{3,128}', signature):
        raise ValueError(f'Unexpected ZTE signature {signature!r}')
    offset += siglen
    header = struct.unpack_from('>15I', data, offset)
    if header[:2] != (PAYLOAD_MAGIC, 6):
        raise ValueError('Expected ZTE Type 6 payload')
    offset += 60
    origlen, cipherlen, next_chunk = struct.unpack_from('>III', data, offset)
    offset += 12
    if (next_chunk != 0 or cipherlen % 16 != 0 or origlen > cipherlen
            or offset+cipherlen > len(data) or origlen < 60):
        raise ValueError('Unexpected ciphertext layout')
    key = hashlib.sha256(backup_password.encode('utf-8')).digest()
    iv = hashlib.sha256(ZTE_IV).digest()[:16]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    inner = (dec.update(bytes(data[offset:offset+cipherlen])) + dec.finalize())[:origlen]
    return unpack_zte_chunks(inner)



def decrypt_internal_config(blob: bytes, gpon_sn: str, router_mac: str) -> bytes:
    """Decrypt the router's native Type-6 user DB without modifying the router.

    This is NOT the WEB backup encryption: the key uses the router GPON serial
    suffix and its own MAC1 (byte-reversed). The PC's MAC is irrelevant here.
    """
    if len(blob) < 88 or len(blob) > 32_000_000:
        raise ValueError('Unexpected internal DB size')
    magic, kind = struct.unpack_from('>II', blob)
    if (magic, kind) != (PAYLOAD_MAGIC, 6):
        raise ValueError('Internal file is not a raw Type-6 ZTE DB')
    plain_len, cipher_len, following = struct.unpack_from('>III', blob, 60)
    if (plain_len < 60 or cipher_len % 16 or plain_len > cipher_len or
            cipher_len != len(blob)-72 or following != 0):
        raise ValueError('Unexpected encrypted internal DB layout')

    serial = gpon_sn.strip().upper()
    if re.fullmatch(r'[A-Z]{4}[0-9A-F]{8}', serial):
        serial = serial[4:]
    if not re.fullmatch(r'[0-9A-F]{8}', serial):
        raise ValueError('GPON serial suffix must contain exactly 8 hex digits')
    mac_text = router_mac.replace(':', '').replace('-', '').strip()
    if not re.fullmatch(r'[0-9A-Fa-f]{12}', mac_text):
        raise ValueError('Router MAC1 is not a valid six-byte MAC')
    key_material = serial + bytes.fromhex(mac_text)[::-1].hex()
    key = hashlib.sha256(key_material.encode('ascii')).digest()
    iv = hashlib.sha256(ZTE_IV).digest()[:16]
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    unwrapped = (decryptor.update(blob[72:]) + decryptor.finalize())[:plain_len]
    return unpack_zte_chunks(unwrapped)


def extract_internal_identity(raw_telnet: str) -> tuple[str, str]:
    """Read the unaltered GPON serial and MAC1 from `setmac show2`."""
    def get(key: str) -> str | None:
        match = re.search(r'(?im)^\s*'+re.escape(key)+r'\[ID:\s*\d+\]\s+is set to\s+([^\r\n]+)', raw_telnet)
        return match.group(1).strip() if match else None

    vendor, sn, mac = get('VENDORID'), get('GPONSN'), get('MAC1')
    if not sn or not mac:
        raise ValueError('setmac show2 did not return both GPONSN and MAC1')
    return (vendor + sn if vendor else sn), mac



def records(xml: bytes, include_defaults: bool = False) -> dict[str, list[dict]]:
    """Parse ZTE rows, optionally preserving the firmware's defval attributes.

    The val attribute is the configured value. The defval attribute is the
    firmware-provided default; it is not inferred from external password lists.
    """
    root = ET.fromstring(xml)
    result: dict[str, list[dict]] = {}
    for table in root.findall('Tbl'):
        table_rows = []
        for row in table.findall('Row'):
            values = {el.attrib['name']: el.attrib.get('val', el.text or '')
                      for el in row if 'name' in el.attrib}
            if include_defaults:
                values['_defaults'] = {
                    el.attrib['name']: el.attrib['defval']
                    for el in row if 'name' in el.attrib and 'defval' in el.attrib
                }
            table_rows.append(values)
        result[table.attrib['name']] = table_rows
    return result

def find_admin_password(user_tables: dict) -> str:
    for entry in user_tables.get('DevAuthInfo', []):
        if (entry.get('User', '').lower() == 'admin' and
                entry.get('Enable') == '1' and entry.get('Level') == '1' and
                entry.get('Pass')):
            return entry['Pass']
    raise ValueError('Active admin password not found in DevAuthInfo')


class Router:
    def __init__(self, address: str, profile_name: str = DEFAULT_PROFILE):
        if profile_name not in WEB_PROFILES:
            raise ValueError(f'Unknown WEB profile: {profile_name}')
        ip = ipaddress.ip_address(address)
        if not ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError('Router must have a private/local IP address')
        self.base = f'http://{address}' if ip.version == 4 else f'http://[{address}]'
        self.profile = WEB_PROFILES[profile_name]
        self.s = requests.Session()
        self.s.trust_env = False  # no corporate/Internet proxy for local credentials
        self.s.headers.update({'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125 Safari/537.36'})
        self.tmp_token = ''
        self.home_html = ''

    def get(self, tag: str = '', typ: str = '', **params):
        p = {'_type':typ, '_tag':tag, **params} if tag else None
        r = self.s.get(self.base+'/', params=p, timeout=TIMEOUT,
                       headers={'X-Requested-With': 'XMLHttpRequest', 'Accept': '*/*'} if typ == 'menuData' else None)
        r.raise_for_status()
        return r

    @staticmethod
    def token_from_page(page: str) -> str:
        match = re.search(r'var\s+_sessionTmpToken\s*=\s*"([^"\r\n]+)"', page)
        if not match:
            raise ValueError('Could not find session token in router page')
        return codecs.decode(match.group(1), 'unicode_escape')

    def login(self, username: str, password: str, expected_right: str | None = None):
        self.get()  # initial cookie + login JS
        j = self.s.get(self.base + self.profile['login_entry'], timeout=TIMEOUT).json()
        sess = j.get('sess_token')
        if not sess:
            raise ValueError('Login token unavailable (already logged in or incompatible firmware)')
        nonce_xml = self.s.get(self.base + self.profile['login_token'], timeout=TIMEOUT).text
        nonce_root = ET.fromstring(nonce_xml)
        nonce = ''.join(nonce_root.itertext()).strip()
        if not nonce:
            raise ValueError('Empty login challenge')
        hashed = hashlib.sha256((password+nonce).encode('utf-8')).hexdigest()
        resp = self.s.post(self.base+self.profile['login_entry'],
                           data={'action':'login', 'Password':hashed, 'Username':username,
                                 '_sessionTOKEN':sess}, timeout=TIMEOUT)
        resp.raise_for_status()
        result = resp.json()
        if not result.get('login_need_refresh'):
            raise ValueError('Login rejected by router (incorrect credentials or session restrictions)')
        self.home_html = self.get().text
        m = re.search(r'\bcurRight\s*=\s*["\'](\d+)["\']', self.home_html)
        right = m.group(1) if m else None
        if expected_right is not None and right != expected_right:
            raise ValueError(f'Logged-in access level is {right!r}, expected {expected_right!r}')
        self.tmp_token = self.token_from_page(self.home_html)
        return right

    def _public_key(self):
        m = re.search(r'function\s+asyEncode\(srcStr\).*?\bvar\s+pubKey\s*=\s*("(?:\\.|[^"\\])*")',
                      self.home_html, re.S)
        if not m:
            raise ValueError('Cannot find current firmware RSA encryption key in web JavaScript')
        encoded = json.loads(m.group(1))
        return serialization.load_pem_public_key(encoded.encode('ascii'))

    def export_backup(self, backup_password: str) -> bytes:
        page = self.get(self.profile['backup_page'], 'menuView', Menu3Location='0').text
        tok = re.search(r'<input\b[^>]*\bid="TOKEN_DOWNLOAD"[^>]*\bvalue="([^"]+)"', page, re.I)
        if not tok:
            raise ValueError('Backup page token missing; wrong permissions or firmware')
        download_token = html.unescape(tok.group(1))
        # Encryption exactly as in captured Vodafone 2026 page: SJCL PBKDF2-SHA256,
        # AES-128-CCM with 8-byte tag, RSA PKCS1 v1.5 wrapping of key and IV.
        salt = os.urandom(8)
        aeskey = hashlib.pbkdf2_hmac('sha256', b'webOriginVal', salt, 1000, dklen=16)
        nonce = os.urandom(12)
        ciphertext = AESCCM(aeskey, tag_length=8).encrypt(
            nonce, backup_password.encode('utf-8'), b'Additional authenticated data')
        keyinfo = base64.b64encode(aeskey).decode() + '&' + base64.b64encode(nonce).decode()
        wrapped = self._public_key().encrypt(keyinfo.encode('utf-8'), rsa_padding.PKCS1v15())
        # Reproduce *exactly* the JS postData string, including its leading '&'.
        # Firmware V14 has commConf.IntegCheck=true; the router verifies a
        # separate Check header: RSA_PKCS1v15(SHA256(raw_post_body).hexdigest()).
        encoded_secret = quote(base64.b64encode(ciphertext).decode('ascii'), safe="~()*!.'-")
        encoded_key = quote(base64.b64encode(wrapped).decode('ascii'), safe="~()*!.'-")
        post_body = ('&sessToken=' + download_token + '&Comment=F6600PBackup'
                     + '&Password=' + encoded_secret + '&encode=' + encoded_key
                     + '&_sessionTOKEN=' + self.tmp_token)
        headers = {'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8'}
        if re.search(r'"IntegCheck"\s*:\s*true', self.home_html):
            integrity = hashlib.sha256(post_body.encode('utf-8')).hexdigest()
            check = self._public_key().encrypt(integrity.encode('ascii'), rsa_padding.PKCS1v15())
            headers['Check'] = base64.b64encode(check).decode('ascii')
        permit = self.s.post(self.base+self.profile['prepare_backup'],
                             data=post_body.encode('ascii'), headers=headers, timeout=TIMEOUT)
        permit.raise_for_status()
        # Router returns an XML success envelope when it accepts the request.
        permit_xml = ET.fromstring(permit.content)
        p = {c.tag:(c.text or '') for c in permit_xml}
        if p.get('IF_ERRORSTR','').upper() != 'SUCC' or p.get('IF_ERRORID','0') != '0':
            raise ValueError(f'Backup preparation rejected: {p.get("IF_ERRORSTR", "unknown")[:100]}')
        # HTML form named fDownload; order of fields as in browser DOM:
        # vdfCfgConfig (empty hidden input), then TOKEN_DOWNLOAD.
        # urllib3 encodes two ordinary multipart form fields (no filename).
        body, content_type = encode_multipart_formdata([
            ('vdfCfgConfig', ''), ('TOKEN_DOWNLOAD', download_token)
        ])
        response = self.s.post(self.base+self.profile['download_backup'],
                               data=body, headers={'Content-Type':content_type},
                               timeout=(5,90))
        if MAGIC not in response.content or len(response.content) < 256 or response.status_code != 200:
            message = ''
            try:
                root = ET.fromstring(response.content)
                message = root.findtext('IF_ERRORSTR') or root.findtext('IF_ERRORTYPE') or ''
            except ET.ParseError:
                if b'SessionTimeout' in response.content:
                    message = 'SessionTimeout'
            raise ValueError('Backup download failed: HTTP %s, %s bytes, %s%s' % (
                response.status_code, len(response.content),
                response.headers.get('Content-Type', 'unknown content type'),
                ', response: ' + message[:100] if message else ''))
        return response.content

    def logout(self):
        if self.tmp_token:
            try:
                self.s.post(self.base+self.profile['logout'],
                            data={'IF_LogOff':'1', '_sessionTOKEN':self.tmp_token}, timeout=TIMEOUT)
            except requests.RequestException:
                pass
        self.s.close()



def backup_password_new() -> str:
    """Only used in RAM: both downloads are decrypted before this program exits."""
    alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
    return 'Zb4' + ''.join(secrets.choice(alphabet) for _ in range(21))



def extract_serial_from_header(blob: bytes) -> str | None:
    """Board S/N is 4 vendor ASCII bytes followed by 4 serial bytes."""
    pos = blob.find(MAGIC)
    header = blob[:pos] if pos >= 0 else b''
    m = re.search(rb'Board S/N\s*:\s*([0-9A-Fa-f]{16})', header)
    if not m:
        return None
    try:
        value = bytes.fromhex(m.group(1).decode('ascii'))
        if all(32 <= c < 127 for c in value[:4]):
            return value[:4].decode('ascii') + value[4:].hex().upper()
    except (ValueError, UnicodeError):
        pass
    return None


def display(v: object) -> str:
    """Stable one-line representation in TXT (no tab/newline injection)."""
    if v is None or v == '':
        return '(not provided)'
    return str(v).replace('\\', '\\\\').replace('\r', '\\r').replace('\n', '\\n').replace('\t', '\\t')


def default_password_lines(row: dict, field: str, label: str = 'Default password') -> list[str]:
    """Read the default of this exact password field from its DM defval.

    Missing or empty defaults are never guessed or replaced with vendor-wide
    credentials. Keep the configured value and its default adjacent.
    """
    default = row.get('_defaults', {}).get(field)
    if default is None or default == '':
        return []
    return ['  ' + label + ': ' + display(default)]

def enabled_label(value: str | None) -> str:
    return {'1': 'Enabled', '0': 'Disabled'}.get(str(value), display(value))


def extract_router_mac(data: dict[str, list[dict]]) -> str | None:
    """Extract the device's base MAC from its own Ethernet interface tables.

    Never fall back to client, bridge-neighbor, or Wi-Fi station MACs.
    User-only backups may omit these tables entirely.
    """
    for table in ('EthLink', 'EthPortConfProduct'):
        for row in data.get(table, []):
            value = str(row.get('MACAddress') or '').strip()
            if re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', value):
                if value.lower() not in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'):
                    return value.lower()
    return None


def make_credentials_text(xml: bytes, admin_blob: bytes,
                          statuses: dict | None = None) -> str:
    data = records(xml, include_defaults=True)
    lines = []
    gpon = extract_serial_from_header(admin_blob)
    mac = extract_router_mac(data)
    if gpon:
        lines.append('GPON Serial Number: ' + gpon)
    if mac:
        lines.append('Router MAC Address: ' + mac)
    elif gpon:
        lines.append('Router MAC Address: (not provided)')
    lines.append('')

    sections: dict[str, list[list[str]]] = {}

    def section(name: str, rows: list[list[str]]) -> None:
        if rows:
            sections[name] = rows

    vlan_by_id = {x.get('ViewName'): x for x in data.get('EthVlan', [])}
    ppp_by_id = {x.get('ViewName'): x for x in data.get('PPPIF', [])}
    wan_rows: list[list[str]] = []
    current_statuses = statuses or {}
    wan = sorted(data.get('WANCPPP', []), key=lambda x: (
        current_statuses.get(x.get('WANCName', ''), '') != 'Connected',
        x.get('WANCName', '')))
    for w in wan:
        p = ppp_by_id.get(w.get('PPPInterface'), {})
        v = vlan_by_id.get(w.get('EthVlan') or p.get('LowerLayers'), {})
        row = [f'Profile: {display(w.get("WANCName"))}',
               f'  PPPoE username: {display(p.get("Username"))}',
               f'  PPPoE password: {display(p.get("Password"))}']
        row.extend(default_password_lines(p, 'Password'))
        row.append('  VLAN ID: ' + display(v.get('VLANID')))
        if '8021Priority' in v:
            row.append('  VLAN priority: ' + display(v['8021Priority']))
        if w.get('WANCName') in current_statuses:
            row.append('  Connection status: ' + display(current_statuses[w['WANCName']]))
        wan_rows.append(row)
    if not wan_rows:
        for i, p in enumerate(data.get('PPPIF', []), 1):
            v = vlan_by_id.get(p.get('LowerLayers'), {})
            row = [f'PPPoE interface {i}:',
                   '  Username: ' + display(p.get('Username')),
                   '  Password: ' + display(p.get('Password'))]
            row.extend(default_password_lines(p, 'Password'))
            row.append('  VLAN ID: ' + display(v.get('VLANID')))
            wan_rows.append(row)
    section('INTERNET / PPPoE / VLAN', wan_rows)

    account_rows: list[list[str]] = []
    accounts = sorted(data.get('DevAuthInfo', []), key=lambda row: (
        row.get('Enable') != '1', row.get('Level') != '1', row.get('User', '')))
    for i, a in enumerate(accounts, 1):
        row = [f'Account {i}: {display(a.get("User"))}',
               '  Password: ' + display(a.get('Pass'))]
        row.extend(default_password_lines(a, 'Pass'))
        row.extend(['  Access level: ' + display(a.get('Level')),
                    '  Status: ' + enabled_label(a.get('Enable'))])
        if a.get('AppID'):
            row.append('  AppID: ' + display(a['AppID']))
        account_rows.append(row)
    section('ROUTER ACCOUNTS', account_rows)

    ssh_rows: list[list[str]] = []
    for r in data.get('SSHCfg', []):
        row = ['SSH:',
               '  Username: ' + display(r.get('SSH_UserName')),
               '  Password: ' + display(r.get('SSH_PassWord'))]
        row.extend(default_password_lines(r, 'SSH_PassWord'))
        row.extend(['  Port: ' + display(r.get('SSH_Port')),
                    '  Status: ' + enabled_label(r.get('SSH_Enable'))])
        ssh_rows.append(row)
    for r in data.get('TelnetCfg', []):
        row = ['Telnet:',
               '  Username: ' + display(r.get('TS_UName')),
               '  Password: ' + display(r.get('TS_UPwd'))]
        row.extend(default_password_lines(r, 'TS_UPwd'))
        row.extend(['  Port: ' + display(r.get('TS_Port')),
                    '  LAN: ' + enabled_label(r.get('Lan_Enable'))])
        ssh_rows.append(row)
    section('SSH / TELNET', ssh_rows)

    acs_rows: list[list[str]] = []
    for r in data.get('MgtServer', []):
        row = ['ACS / TR-069:',
               '  URL: ' + display(r.get('URL')),
               '  Username: ' + display(r.get('UserName')),
               '  Password: ' + display(r.get('Password'))]
        row.extend(default_password_lines(r, 'Password'))
        row.extend(['  Connection request username: ' + display(r.get('ConnectionRequestUsername')),
                    '  Connection request password: ' + display(r.get('ConnectionRequestPassword'))])
        row.extend(default_password_lines(r, 'ConnectionRequestPassword',
                                          label='  Connection request default password'.strip()))
        if r.get('PKCS12PassWord'):
            row.append('  PKCS#12 password: ' + display(r['PKCS12PassWord']))
            row.extend(default_password_lines(r, 'PKCS12PassWord',
                                              label='Default PKCS#12 password'))
        acs_rows.append(row)
    section('REMOTE MANAGEMENT', acs_rows)

    sip_rows: list[list[str]] = []
    for i, a in enumerate(data.get('VoIPSIPLine', []), 1):
        if not any(a.get(k) for k in ('AuthUserName', 'AuthPassword', 'DigestUserName')):
            continue
        row = [f'SIP line {i}:',
               '  Username: ' + display(a.get('AuthUserName')),
               '  Password: ' + display(a.get('AuthPassword'))]
        row.extend(default_password_lines(a, 'AuthPassword'))
        for key in ('DigestUserName', 'AuthUserName3', 'DisplayName'):
            if a.get(key):
                row.append('  ' + key + ': ' + display(a[key]))
        sip_rows.append(row)
    for a in data.get('VoIPSIPServer', []):
        server = [f'  {key}: {display(a[key])}' for key in (
            'ProxyServer1', 'ProxyServerPort1', 'RegistrarServer1',
            'RegistrarServerPort1', 'OutboundProxy1', 'OutboundProxyPort1') if a.get(key)]
        if server:
            sip_rows.append(['SIP servers:'] + server)
    section('VOIP / SIP', sip_rows)

    extras: list[list[str]] = []
    for table, u, pw in (
        ('FTPUser', 'Username', 'Password'),
        ('SambaUser', 'UserName', 'PassWord'),
        ('DDNSClient', 'Username', 'Password'),
    ):
        for i, r in enumerate(data.get(table, []), 1):
            if not r.get(u) and not r.get(pw):
                continue
            row = [f'{table} {i}:',
                   '  Username: ' + display(r.get(u)),
                   '  Password: ' + display(r.get(pw))]
            row.extend(default_password_lines(r, pw))
            extras.append(row)
    section('FTP / SAMBA / DDNS', extras)

    wifi_by_id = {r.get('ViewName'): r for r in data.get('WLANCfg', [])}
    wifi_rows: list[list[str]] = []
    for p in data.get('WLANPSK', []):
        w = wifi_by_id.get(p.get('WLANViewName'), {})
        if w.get('Enable') != '1':
            continue
        secret_field = 'KeyPassphrase' if p.get('KeyPassphrase') else 'PreSharedKey'
        secret = p.get(secret_field)
        if not secret:
            continue
        row = ['SSID: ' + display(w.get('ESSID')),
               '  Wi-Fi password: ' + display(secret)]
        row.extend(default_password_lines(p, secret_field))
        wifi_rows.append(row)
    section('WI-FI', wifi_rows)

    order = ('ROUTER ACCOUNTS', 'SSH / TELNET', 'INTERNET / PPPoE / VLAN',
             'REMOTE MANAGEMENT', 'VOIP / SIP', 'FTP / SAMBA / DDNS', 'WI-FI')
    for name in order:
        rows = sections.get(name, [])
        if not rows:
            continue
        lines.append('=== ' + name + ' ===')
        for row in rows:
            lines.extend(row)
            lines.append('')
    return '\n'.join(lines).rstrip() + '\n'


# AES-192 key pools and factory protocol model adapted from
# langit7/zte-modem-tools-gui (AGPL-3.0), with credit above.
_KEY_POOLS = [
 bytes.fromhex('''
 7B 56 B0 F7 DA 0E 68 52 C8 19 F3 2B 84 90 79 E5 62 F8 EA D2
 64 93 87 DF 73 D7 FB CC AA FE 75 43 1C 29 DF 4C 52 2C 6E 7B
 45 3D 1F F1 DE BC 27 85 8A 45 91 BE 38 13 DE 67 32 08 54 11
 75 F4 D3 B4 A4 B3 12 86 67 23 99 4C 61 7F B1 D2 30 DF 47 F1
 76 93 A3 8C 95 D3 59 BF 87 8E F3 B3 E4 76 49 88'''),
 bytes.fromhex('''
 8C 23 65 D1 FC 32 45 37 11 28 71 63 07 20 69 14 73 E7 D4 53
 13 24 36 C2 B5 E1 FC CF 8A 9A 41 89 3C 49 CF 5C 72 8C 9E EB
 75 0D 3F D1 FE CC 57 65 7A 35 21 3E 68 53 7E 97 02 48 74 71
 95 34 53 84 B4 C3 E2 D6 27 3D E6 5D 72 9C BC 3D 03 FD 76 C1
 9C 25 A8 92 47 E4 18 0F 24 3F 4F 67 EC 97 F4 99'''),
 bytes.fromhex('''
 9C 33 75 D1 1C 42 45 37 18 48 91 73 17 45 79 44 43 D7 D5 73
 33 54 76 D2 C5 F1 2C 4F 7A BA 61 D9 5C 69 DF 8C D2 1C DE 3B
 35 2D 2F E1 DE 4C 77 F5 1A 65 D1 FE 18 43 8E A7 42 08 04 78
 D5 E4 F3 34 A4 D3 F2 36 47 6D 86 9D 42 65 13 42 DC 42 99 48
 DC 67 9F 9E DC 46 37 5F 84 9F 6F 76 CE 79 4F 49'''),
]


def route_interface(ip: str) -> tuple[str, bytes]:
    """Return the IPv4 source IP and MAC of precisely that local interface."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.connect((ip, 80))
        source = udp.getsockname()[0]
    matched = []
    for name, entries in psutil.net_if_addrs().items():
        ipv4 = any(e.family == socket.AF_INET and e.address == source for e in entries)
        if ipv4:
            candidates = [e.address for e in entries if e.family == psutil.AF_LINK]
            for candidate in candidates:
                mac = re.sub(r'[^0-9a-fA-F]', '', candidate)
                if len(mac) == 12:
                    matched.append((name, bytes.fromhex(mac)))
    if len(matched) != 1 or matched[0][1] == b'\0'*6:
        raise ValueError('Cannot uniquely identify the source interface MAC')
    return source, matched[0][1]


def proof_for_mac(method: int, bridge: bytes, mac: bytes) -> bytes:
    """Encode a single MAC proof, with no fallback/probing of other adapters."""
    if method == 2:
        backwards = {}
        for value in range(0x9e9):
            backwards.setdefault(pow(value, 0x4f7, 0x9e9) & 255, value)
        if any(b not in backwards for b in mac):
            raise ValueError('Unable to encode client MAC for factory method 2')
        result = bytearray(46)
        for i, byte in enumerate(mac):
            struct.pack_into('<I', result, i*4, backwards[byte])
        return bytes(result)
    if method == 3:
        if len(bridge) != 6:
            raise ValueError('Invalid factory method 3 bridge identifier')
        values = ([0, 1, 0, 9893] +
                  list(bridge+mac+mac+bytes.fromhex('00FF7246341100FF72463411')))
        return b''.join(struct.pack('<I', x) for x in values)
    raise ValueError(f'Unsupported factory method {method}')


def _aes_ecb(key: bytes, content: bytes, decrypt: bool = False) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    op = cipher.decryptor() if decrypt else cipher.encryptor()
    if not decrypt:
        content += b'\0' * (-len(content) % 16)
    elif len(content) % 16:
        # Some ZTE builds truncate authentication response at a null byte.
        content += b'\0' * (-len(content) % 16)
    return op.update(content) + op.finalize()


def probe_existing_telnet(ip: str) -> tuple[str, socket.socket | None]:
    """Keep a responsive TCP connection for login; treat TCP timeout as dormant.

    On this F6600P, TCP/23 can time out while the factory Telnet service is
    temporarily unresponsive. A refused connection can also mean unavailable.
    Either outcome permits ONE factory activation attempt during this run.
    Other network errors remain inconclusive and must not trigger activation.
    """
    try:
        sock = socket.create_connection((ip, 23), timeout=4)
        sock.settimeout(0.6)
        return 'open', sock
    except (ConnectionRefusedError, TimeoutError):
        return 'unresponsive', None
    except OSError as exc:
        raise ConnectionError(
            f'TCP/23 state is uncertain ({type(exc).__name__}: {exc}); '
            'factory activation skipped'
        ) from exc


class FactoryTelnet:
    """Single factory-mode session; temporary activation only."""
    def __init__(self, ip: str, factory_user: str, factory_password: str, mac: bytes,
                 profile_name: str = DEFAULT_PROFILE):
        self.ip = ip
        self.profile = WEB_PROFILES[profile_name]
        self.user = factory_user
        self.password = factory_password
        self.mac = mac
        self.base = f'http://{ip}'
        self.http = requests.Session()
        self.http.trust_env = False
        self.http.headers.update({'User-Agent': 'Mozilla/5.0', 'Referer': f'{self.base}/login.html'})
        self.key: bytes | None = None
        self.credentials: tuple[str, str] | None = None

    def _post(self, path: str, raw: bytes) -> requests.Response:
        r = self.http.post(self.base + path, data=raw,
                           headers={'Content-Type': 'application/octet-stream'},
                           timeout=(5, 12), allow_redirects=False)
        return r

    def _encrypted(self, command: str) -> requests.Response:
        if self.key is None:
            raise ValueError('Factory mode is not authenticated')
        return self._post(self.profile['factory_commands'], _aes_ecb(self.key, command.encode('utf-8')))

    def _authenticated(self) -> None:
        # A failed previous step is reset with an intentionally invalid request.
        try:
            self.http.get(self.base + '/', timeout=(5, 8))
        except requests.RequestException:
            pass
        reset = self._post(self.profile['factory_handshake'], b'SendSq.gch')
        if reset.status_code not in (200, 400):
            raise ValueError(f'Factory reset handshake HTTP {reset.status_code}')
        try:
            self._post(self.profile['factory_handshake'], b'RequestFactoryMode.gch')
        except requests.ConnectionError:
            pass
        rand = secrets.randbelow(60)
        sq = self._post(self.profile['factory_handshake'], f'SendSq.gch?rand={rand}\r\n'.encode('ascii'))
        if sq.status_code != 200:
            raise ValueError(f'Factory handshake rejected (HTTP {sq.status_code})')
        bridge = b''
        if not sq.content:
            method, index = 1, rand
        elif sq.content.startswith(b'newrand='):
            try:
                rerand = int(sq.content.split(b'=', 1)[1])
            except ValueError as exc:
                raise ValueError('Unexpected factory newrand value') from exc
            method, index = 2, (((0x1000193 * rand) & 63) ^ rerand) % 60
        else:
            m = re.fullmatch(rb're_rand=(\d+)&(\d+)&(.{6})', sq.content, re.S)
            if m is None:
                raise ValueError('Unsupported factory handshake response')
            rerand = int(m.group(1))
            bridge = m.group(3)
            method, index = 3, (((0x1000193 * rand) & 63) ^ rerand) % 60
        pool = _KEY_POOLS[method-1]
        self.key = bytes(b ^ 0xa5 for b in pool[index:index+24])
        if len(self.key) != 24:
            raise ValueError('Factory protocol key is incomplete')
        if method != 1:
            count = 12 if method == 2 else 34
            payload = f'SendInfo.gch?info={count}|'.encode('ascii') + proof_for_mac(method, bridge, self.mac)
            r = self._post(self.profile['factory_commands'], _aes_ecb(self.key, payload))
            if r.status_code != 200:
                raise ValueError(f'Factory MAC proof rejected (HTTP {r.status_code})')
        check = self._encrypted(f'CheckLoginAuth.gch?version50&user={self.user}&pass={self.password}')
        if check.status_code != 200:
            raise ValueError(f'Factory credentials rejected (HTTP {check.status_code})')
        response = _aes_ecb(self.key, check.content, decrypt=True).rstrip(b'\0')
        if not response.startswith(b'FactoryMode.gch'):
            raise ValueError('Invalid factory authentication response')

    def open(self) -> tuple[str, str]:
        self._authenticated()
        r = self._encrypted('FactoryMode.gch?mode=2&user=notused')
        if r.status_code != 200:
            raise ValueError(f'Temporary Telnet activation rejected (HTTP {r.status_code})')
        answer = _aes_ecb(self.key, r.content, decrypt=True).rstrip(b'\0').decode('utf-8', 'replace')
        m = re.search(r'[?&]user=([^&\s]+)&pass=([^&\s]+)', answer)
        if not m:
            raise ValueError('Factory reply does not contain temporary Telnet credentials')
        self.credentials = (m.group(1), m.group(2))
        return self.credentials

    def request_close(self) -> None:
        """Request Telnet closure with a fresh factory login.

        Only an HTTP 200 response with an empty body is accepted. No TCP/23
        probe or retries are performed. Connection errors remain failures.
        """
        self.key = None
        self._authenticated()
        response = self._encrypted('FactoryMode.gch?close')
        if response.status_code != 200 or response.content:
            raise ValueError('Factory close request was not acknowledged')


class TelnetShell:
    """Minimal Telnet client supporting existing interactive login sessions.

    A live TCP socket can be passed in, avoiding an extra probe connection.
    The client handles IAC negotiation and several common prompt formats.
    """

    LOGIN = re.compile(rb'(?:login|user\s*name|username)\s*:\s*', re.I)
    PASSWORD = re.compile(rb'password\s*:\s*', re.I)
    PROMPT = re.compile(rb'(?:^|[\r\n])[^\r\n]{0,120}[#$>]\s*$', re.M)
    AUTH_FAILED = re.compile(rb'(?:login incorrect|authentication failed|invalid password|login failed)', re.I)

    def __init__(self, host: str, username: str, password: str,
                 existing_socket: socket.socket | None = None):
        self.sock = existing_socket or socket.create_connection((host, 23), timeout=8)
        self.sock.settimeout(0.5)
        self.state = 0
        self._negotiation = 0
        self._buffer = bytearray()
        self.authenticated = False
        try:
            # Some implementations do not send their first prompt until they
            # receive a carriage return. Nudge once only if initially silent.
            initial, _ = self._expect((self.LOGIN, self.PROMPT), 20,
                                      'login prompt', nudge_when_silent=True)
            if initial == 1:  # A shell prompt with no login challenge.
                self.authenticated = True
                return
            self._send(username)
            next_step, _ = self._expect((self.PASSWORD, self.PROMPT, self.LOGIN,
                                        self.AUTH_FAILED), 15, 'password prompt')
            if next_step == 1:
                self.authenticated = True
                return  # Passwordless account.
            if next_step in (2, 3):
                raise ValueError('Telnet rejected the username')
            self._send(password)
            final, _ = self._expect((self.PROMPT, self.LOGIN, self.AUTH_FAILED),
                                    20, 'shell prompt')
            if final != 0:
                raise ValueError('Telnet rejected the credentials')
            self.authenticated = True
        except Exception:
            self.close()
            raise

    def close(self):
        """Log out of an authenticated shell, then release the TCP connection.

        Only the local Telnet session is closed. The remote Telnet service is
        never disabled and no factory-mode close command is sent.
        """
        sock = self.sock
        if sock is None:
            return
        self.sock = None
        try:
            if self.authenticated:
                try:
                    sock.sendall(b'exit\r\n')
                except OSError:
                    pass
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            sock.settimeout(0.25)
            deadline = time.monotonic() + 1.0
            while time.monotonic() < deadline:
                try:
                    if not sock.recv(2048):
                        break
                except (OSError, socket.timeout):
                    break
        finally:
            sock.close()

    def _send(self, text: str):
        self.sock.sendall(text.encode('utf-8') + b'\r\n')

    def _filter(self, data: bytes) -> bytes:
        result = bytearray()
        for b in data:
            if self.state == 0:
                if b == 255: self.state = 1
                else: result.append(b)
            elif self.state == 1:
                if b == 255: result.append(255); self.state = 0
                elif b in (251, 252, 253, 254): self._negotiation = b; self.state = 2
                elif b == 250: self.state = 3
                else: self.state = 0
            elif self.state == 2:
                reply = 254 if self._negotiation in (251, 252) else 252
                try: self.sock.sendall(bytes([255, reply, b]))
                except OSError: pass
                self.state = 0
            elif self.state == 3:
                if b == 255: self.state = 4
            elif self.state == 4:
                self.state = 0 if b == 240 else 3
        return bytes(result)

    def _expect(self, patterns: tuple[re.Pattern, ...], seconds: float,
                stage: str, nudge_when_silent: bool = False,
                cap: int = 2_000_000) -> tuple[int, bytes]:
        deadline = time.monotonic() + seconds
        start = time.monotonic()
        nudged = False
        received = len(self._buffer)
        while time.monotonic() < deadline:
            buf = bytes(self._buffer)
            for index, pattern in enumerate(patterns):
                match = pattern.search(buf)
                if match:
                    consumed = buf[:match.end()]
                    del self._buffer[:match.end()]
                    return index, consumed
            if nudge_when_silent and not nudged and not received and time.monotonic() - start > 8.0:
                self.sock.sendall(b'\r\n')
                nudged = True
            try:
                packet = self.sock.recv(8192)
            except socket.timeout:
                continue
            if not packet:
                raise ConnectionError(f'Telnet disconnected while waiting for {stage}')
            filtered = self._filter(packet)
            received += len(filtered)
            self._buffer.extend(filtered)
            if len(self._buffer) > cap:
                raise ValueError(f'Telnet response too large while waiting for {stage}')
        # Avoid printing a received login banner or any secrets to the console.
        message = f'Telnet timed out waiting for {stage} ({received} bytes received)'
        if stage == 'login prompt':
            message += '; close any active PuTTY session and retry'
        raise TimeoutError(message)

    def command(self, command: str) -> str:
        marker = '__ZTE_EXPORT_' + secrets.token_hex(8) + '__'
        self._send(command)
        self._send(f'printf "\\n{marker}\\n"')
        pattern = re.compile(rb'[\r\n]' + marker.encode() + rb'[\r\n]')
        _, content = self._expect((pattern,), 25, f'output of {command}')
        text = re.split(pattern, content, maxsplit=1)[0]
        return clean_telnet_output(text.decode('utf-8', 'replace'), command, marker)


def clean_telnet_output(text: str, command: str, marker: str) -> str:
    """Remove local shell echoes, sync markers and trailing BusyBox prompts."""
    cleaned = []
    for raw in text.replace('\r', '').replace('\0', '').split('\n'):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            cleaned.append('')
            continue
        # BusyBox shell may echo the command with or without a prompt.
        if stripped == command or re.fullmatch(r'[^\n]*[#$]\s*' + re.escape(command), stripped):
            continue
        if marker in stripped and 'printf' in stripped:
            continue
        if re.fullmatch(r'(?:[/~\w.-]+\s+)?[#$]', stripped):
            continue
        cleaned.append(line)
    return '\n'.join(cleaned).strip('\n')


DB_USER_CONFIG = '/userconfig/cfg/db_user_cfg.xml'


def telnet_fetch_user_config(shell: TelnetShell) -> bytes:
    """Transfer the existing file using printable base64; no remote writes."""
    errors = []
    for encoder in ('base64', 'busybox base64'):
        try:
            output = shell.command(f'{encoder} {DB_USER_CONFIG}')
            payload = re.sub(r'\s+', '', output)
            if not payload:
                raise ValueError('empty base64 output')
            data = base64.b64decode(payload, validate=True)
            if not (1 <= len(data) <= 2_000_000):
                raise ValueError('unexpected file length')
            size_text = shell.command(f'wc -c < {DB_USER_CONFIG}')
            match = re.search(r'(?m)^\s*(\d+)\s*$', size_text)
            if match and int(match.group(1)) != len(data):
                raise ValueError('remote file length mismatch')
            # The remote sha256sum utility is optional on BusyBox builds.
            digest_text = shell.command(f'sha256sum {DB_USER_CONFIG}')
            match = re.search(r'(?m)^([0-9a-fA-F]{64})\s+', digest_text)
            if match and hashlib.sha256(data).hexdigest().lower() != match.group(1).lower():
                raise ValueError('remote checksum mismatch')
            return data
        except (ValueError, TimeoutError, ConnectionError, OSError) as exc:
            errors.append(f'{encoder}: {type(exc).__name__}: {str(exc)[:80]}')
    raise ValueError('Could not transfer the internal configuration (' + '; '.join(errors) + ')')


def telnet_readout(shell: TelnetShell) -> tuple[str, bytes | None]:
    """Read GPON identity and the pre-existing internal config file."""
    chunks = []
    internal_file = None
    try:
        chunks.append('$ setmac show2\n' + shell.command('setmac show2') + '\n')
    except (ValueError, TimeoutError, ConnectionError, OSError) as exc:
        chunks.append('[setmac show2: ' + type(exc).__name__ + ']\n')
        if isinstance(exc, (TimeoutError, ConnectionError, OSError)):
            return '\n'.join(chunks), None
    try:
        internal_file = telnet_fetch_user_config(shell)
    except (ValueError, TimeoutError, ConnectionError, OSError) as exc:
        chunks.append('[Internal file unavailable: ' + str(exc)[:250] + ']\n')
    return '\n'.join(chunks).strip() + '\n', internal_file


def new_output_dir() -> Path:
    stamp = datetime.datetime.now().astimezone().strftime('%Y%m%d-%H%M%S')
    base = Path.cwd() / ('zte_export_' + stamp)
    folder, n = base, 1
    while folder.exists():
        folder = Path(str(base) + '_' + str(n))
        n += 1
    folder.mkdir(mode=0o700)
    return folder


def _read_status(router: Router) -> dict[str, str]:
    """Optional read-only status; failure must not prevent config export."""
    result = {}
    try:
        resp = router.get(router.profile['wan_status'], 'menuData')
        root = ET.fromstring(resp.content)
        for group in root:
            for instance in group.findall('Instance'):
                fields = {}
                items = list(instance)
                for index, item in enumerate(items[:-1]):
                    if item.tag == 'ParaName' and items[index+1].tag == 'ParaValue':
                        fields[item.text or ''] = items[index+1].text or ''
                if fields.get('WANCName'):
                    result[fields['WANCName']] = fields.get('ConnStatus', '')
    except (ValueError, ET.ParseError, requests.RequestException):
        pass
    return result


def save_config(out: Path, xml: bytes, blob: bytes,
                statuses: dict[str, str] | None = None) -> None:
    # WEB XML and the credential report are the guaranteed outputs.
    safe_write(out / 'webcfg_dbase.xml', xml)
    try:
        report = make_credentials_text(xml, blob, statuses)
    except Exception as exc:
        report = 'Report error: ' + type(exc).__name__ + '\n'
    safe_write(out / 'webcfg_creds.txt', report.encode('utf-8'))
    Progress.ok('webcfg_dbase.xml, webcfg_creds.txt')


def offline(filename: Path) -> int:
    Progress.title('ZTE configuration export - offline')
    Progress.stage(1, 'Decrypting and validating configuration')
    if not filename.is_file():
        Progress.warn('Backup file not found.')
        return 1
    try:
        blob = filename.read_bytes()
        native = blob[:8] == struct.pack('>II', PAYLOAD_MAGIC, 6)
        raw_xml = blob.lstrip().startswith((b'<?xml', b'<DB'))
        if native:
            serial = input('    > GPON serial (ZTEG...): ').strip()
            mac = input('    > Router MAC1: ').strip()
            xml = decrypt_internal_config(blob, serial, mac)
            name = 'telnet_dbase.xml'
        elif raw_xml:
            xml = blob
            ET.fromstring(xml)
            name = 'webcfg_dbase.xml'
        else:
            password = input('    > Backup password: ')
            if not password:
                raise ValueError('Backup password is required')
            xml = decrypt_backup(blob, password)
            name = 'webcfg_dbase.xml'
        out = new_output_dir()
        safe_write(out / name, xml)
        if native:
            Progress.ok(name)
        else:
            safe_write(out / 'webcfg_creds.txt',
                       make_credentials_text(xml, blob).encode('utf-8'))
            Progress.ok(name + ', webcfg_creds.txt')
        Progress.finish(out)
        return 0
    except (OSError, ValueError, ET.ParseError, struct.error, zlib.error) as exc:
        Progress.warn(f'Offline export failed: {type(exc).__name__}: {exc}')
        return 1


def ask_keep_telnet() -> bool:
    """Default to closing temporary access; EOF also selects the safe default."""
    try:
        answer = input('    > Keep Telnet open? [y/N]: ').strip().lower()
    except (EOFError, KeyboardInterrupt):
        Progress.action('Using default: close Telnet')
        return False
    return answer in ('y', 'yes')


def save_telnet_credentials(out: Path, ip: str, creds: tuple[str, str]) -> None:
    safe_write(out / 'telnet_creds.txt',
               (f'Host: {ip}\nPort: 23\nUsername: {creds[0]}\n'
                f'Password: {creds[1]}\n').encode('utf-8'))


def finish_telnet(ip: str, out: Path, creds: tuple[str, str] | None,
                  factory: FactoryTelnet | None, admin_password: str,
                  access_confirmed: bool, profile_name: str) -> bool:
    """Ask once and request factory closure, without a TCP/23 verification."""
    if not access_confirmed:
        Progress.action('No confirmed Telnet access to manage')
        return True

    if ask_keep_telnet():
        if creds:
            try:
                save_telnet_credentials(out, ip, creds)
                Progress.ok('telnet_creds.txt')
            except OSError as exc:
                Progress.warn(f'Could not save Telnet credentials: {exc}')
        Progress.action('Telnet left enabled; reboot after use')
        return True

    Progress.action('Requesting temporary Telnet closure')
    closer = None
    try:
        # Closing is a new factory operation with the SAME administrator login
        # used for activation, not the temporary Telnet username/password.
        _, mac = route_interface(ip)
        closer = FactoryTelnet(ip, 'admin', admin_password, mac,
                               profile_name=profile_name)
        closer.request_close()
    except (ValueError, requests.RequestException, OSError, TimeoutError) as exc:
        # Never retry the close or infer its success from TCP port 23.
        if creds:
            try:
                save_telnet_credentials(out, ip, creds)
                Progress.ok('telnet_creds.txt')
            except OSError as save_exc:
                Progress.warn(f'Could not save Telnet credentials: {save_exc}')
        Progress.warn(f'Telnet closure failed: {type(exc).__name__}: {exc}')
        return False
    finally:
        if closer is not None:
            closer.http.close()

    Progress.action('Telnet close request accepted')
    return True


def online(profile_name: str = DEFAULT_PROFILE) -> int:
    Progress.title('ZTE configuration export - online')
    Progress.stage(1, 'Router connection')
    ip = input('    > Router IP [192.168.1.1]: ').strip() or '192.168.1.1'
    login_user = input('    > Username [user]: ').strip() or 'user'
    login_password = input('    > Password: ')
    if not login_password:
        Progress.warn('User password is required')
        return 1
    try:
        address = ipaddress.ip_address(ip)
        if address.version != 4 or not address.is_private or address.is_link_local or address.is_loopback:
            raise ValueError('A private IPv4 address is required')
    except ValueError as exc:
        Progress.warn(str(exc))
        return 1

    out = None
    admin_password = None
    status = {}
    session_password = backup_password_new()
    Progress.stage(2, 'WEB configuration')
    try:
        session = Router(ip, profile_name)
        try:
            Progress.action(f'Logging in as {login_user}')
            role = session.login(login_user, login_password)
            status = _read_status(session)
            if role == '1':
                admin_password = login_password
                Progress.action('Downloading administrator backup')
                admin_blob = session.export_backup(session_password)
                admin_xml = decrypt_backup(admin_blob, session_password)
            else:
                Progress.action('Downloading user backup and locating admin account')
                user_blob = session.export_backup(session_password)
                user_xml = decrypt_backup(user_blob, session_password)
                admin_password = find_admin_password(records(user_xml))
        finally:
            session.logout()
        if role != '1':
            Progress.action('Logging in as admin and downloading full backup')
            admin = Router(ip, profile_name)
            try:
                admin.login('admin', admin_password, expected_right='1')
                status = _read_status(admin) or status
                admin_blob = admin.export_backup(session_password)
                admin_xml = decrypt_backup(admin_blob, session_password)
            finally:
                admin.logout()
        out = new_output_dir()
        save_config(out, admin_xml, admin_blob, status)
    except (requests.RequestException, ValueError, ET.ParseError, OSError,
            struct.error, zlib.error, TimeoutError, ConnectionError) as exc:
        Progress.warn(f'WEB export failed: {type(exc).__name__}: {exc}')
        if out:
            Progress.finish(out, 'PARTIAL')
        return 1

    Progress.stage(3, 'Telnet and internal configuration')
    factory: FactoryTelnet | None = None
    shell: TelnetShell | None = None
    existing_socket: socket.socket | None = None
    credentials: tuple[str, str] | None = None
    access_confirmed = False
    internal_text = ''
    internal_data = None
    saved_internal_dbase = False
    saved_show2 = False
    interrupted = False
    try:
        Progress.action('Checking Telnet availability')
        state, existing_socket = probe_existing_telnet(ip)
        already_open = state == 'open'
        if already_open:
            Progress.action('Using existing Telnet session')
            telnet_user = input('    > Telnet username: ').strip()
            telnet_password = input('    > Telnet password: ')
            if not telnet_user or not telnet_password:
                raise ValueError('Telnet username and password are required')
            sock_for_login, existing_socket = existing_socket, None
            try:
                shell = TelnetShell(ip, telnet_user, telnet_password,
                                    existing_socket=sock_for_login)
            except TimeoutError as exc:
                if 'waiting for login prompt' not in str(exc):
                    raise
                already_open = False
                Progress.action('No login prompt; trying a single factory activation')
            else:
                credentials = (telnet_user, telnet_password)
                access_confirmed = True
        if not already_open:
            Progress.action('Opening temporary Telnet via factory interface')
            _, client_mac = route_interface(ip)
            factory = FactoryTelnet(ip, 'admin', admin_password, client_mac,
                                   profile_name=profile_name)
            credentials = factory.open()
            access_confirmed = True  # Factory reported successful activation.

        if shell is None:
            shell = TelnetShell(ip, *credentials)
            access_confirmed = True
        Progress.action('Reading GPON identity and internal database')
        internal_text, internal_data = telnet_readout(shell)
        if internal_data is not None:
            try:
                serial, mac1 = extract_internal_identity(internal_text)
                clear_xml = decrypt_internal_config(internal_data, serial, mac1)
                safe_write(out / 'telnet_dbase.xml', clear_xml)
                saved_internal_dbase = True
            except (OSError, ValueError, ET.ParseError, struct.error, zlib.error) as exc:
                Progress.warn(f'Internal DB decryption unavailable: {type(exc).__name__}: {exc}')
    except KeyboardInterrupt:
        interrupted = True
        Progress.warn('Collection interrupted; proceeding to Telnet cleanup')
    except (requests.RequestException, ValueError, OSError, TimeoutError, ConnectionError) as exc:
        Progress.warn(f'Telnet collection unavailable: {type(exc).__name__}: {exc}')
        internal_text = internal_text or f'Telnet unavailable: {type(exc).__name__}\n'
    finally:
        # Release interactive session *before* closing the listener.
        if shell is not None:
            try:
                shell.close()
            except OSError as exc:
                Progress.warn(f'Telnet TCP disconnect failed: {exc}')
        if existing_socket is not None:
            existing_socket.close()
        try:
            safe_write(out / 'telnet_show2.txt', internal_text.encode('utf-8'))
            saved_show2 = True
        except OSError as exc:
            Progress.warn(f'Could not save Telnet output: {exc}')

    output_files = []
    if saved_show2:
        output_files.append('telnet_show2.txt')
    if saved_internal_dbase:
        output_files.append('telnet_dbase.xml')
    if output_files:
        Progress.ok(', '.join(output_files))

    Progress.stage(4, 'Telnet cleanup')
    verified_or_kept = False
    try:
        verified_or_kept = finish_telnet(ip, out, credentials, factory,
                                         admin_password, access_confirmed,
                                         profile_name)
    finally:
        if factory is not None:
            factory.http.close()

    Progress.finish(out, ('INTERRUPTED' if interrupted else
                          'COMPLETE' if verified_or_kept else 'WITH WARNINGS'))
    return 130 if interrupted else 0 if verified_or_kept else 2


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Export ZTE configuration and collect internal Telnet data when available.')
    parser.add_argument('backup', nargs='?', type=Path,
                        help='Existing .cfg, native Type-6 database, or XML (offline mode).')
    parser.add_argument('--profile', choices=sorted(WEB_PROFILES), default=DEFAULT_PROFILE,
                        help='WEB endpoint profile (online mode).')
    args = parser.parse_args()
    if args.backup:
        return offline(args.backup)
    return online(args.profile)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print('\nInterrupted.', file=sys.stderr)
        raise SystemExit(130)
