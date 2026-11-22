# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
import io
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from xml.etree import ElementTree

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import zte_f6600p_export as exporter


PASSWORD = 'Example backup password'
CHUNK_SIZE = 64 * 1024
XML = b'<DB><Tbl name="Example"><Row No="0"><DM name="Label" val="%s"/></Row></Tbl></DB>'


class WebBackupTest(unittest.TestCase):
    def test_web_container_with_exact_multiple_of_chunk_size(self):
        xml = XML % (b'B' * (2 * CHUNK_SIZE - len(XML % b'')))
        blob = exporter.pack_web_backup(xml, PASSWORD)
        self.assertEqual(blob[:16], bytes.fromhex('999999994444444455555555aaaaaaaa'))
        self.assertEqual(struct.unpack_from('<II', blob, 68), (128, len(blob) - 128))
        self.assertEqual(struct.unpack_from('>III', blob, 128), (0x04030201, 0, 6))
        self.assertEqual(blob[140:146], b'F6600P')
        payload_offset = 146
        self.assertEqual(struct.unpack_from('>II', blob, payload_offset), (0x01020304, 6))
        plain_size, cipher_size, following = struct.unpack_from('>III', blob, payload_offset + 60)
        self.assertEqual((cipher_size, following), (len(blob) - payload_offset - 72, 0))

        key = hashlib.sha256(PASSWORD.encode()).digest()
        iv = hashlib.sha256(b'ZTE%FN$GponNJ025').digest()[:16]
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = dec.update(blob[payload_offset + 72:]) + dec.finalize()
        inner = padded[:plain_size]
        self.assertEqual(padded[plain_size:], bytes(-plain_size % 16))
        header = struct.unpack_from('>15I', inner)
        self.assertEqual(header[:3], (0x01020304, 0, len(xml)))
        self.assertEqual(header[4], CHUNK_SIZE)
        self.assertEqual(header[6], zlib.crc32(inner[:24]))

        pos, crc, clear = 60, 0, bytearray()
        for last in (False, True):
            last_start = pos
            n_plain, n_z, next_chunk = struct.unpack_from('>III', inner, pos)
            compressed = inner[pos + 12:pos + 12 + n_z]
            crc = zlib.crc32(compressed, crc)
            clear.extend(zlib.decompress(compressed))
            pos += 12 + n_z
            self.assertEqual(n_plain, CHUNK_SIZE)
            self.assertEqual(next_chunk, 0 if last else pos)
        self.assertEqual((header[3], header[5], pos), (last_start, crc, len(inner)))
        self.assertEqual(clear, xml)
        self.assertEqual(exporter.decrypt_backup(blob, PASSWORD), xml)

    def test_xml_validation_checks_syntax_only(self):
        for malformed in (b'<DB>', b'<DB value="x",/>', b'<DB>&broken</DB>'):
            with self.subTest(xml=malformed):
                with self.assertRaises(ElementTree.ParseError):
                    exporter.pack_web_backup(malformed, PASSWORD)

        xml = b'<!DOCTYPE Other [<!ENTITY name "example">]><Other>,&name;<Field /></Other>'
        self.assertTrue(exporter.pack_web_backup(xml, PASSWORD))

    def test_offline_xml_output_without_any_prompts(self):
        with tempfile.TemporaryDirectory() as directory:
            for name, output in (('settings.xml', 'settings_repacked.cfg'),
                                 ('guest сеть.v2.XML', 'guest сеть.v2_repacked.cfg'),
                                 ('edited', 'edited_repacked.cfg')):
                with self.subTest(name=name):
                    source = Path(directory) / name
                    source.write_bytes(b'\xef\xbb\xbf<!-- edited -->' + XML % b'new')
                    with patch('builtins.input', side_effect=AssertionError('Unexpected prompt')), \
                            redirect_stdout(io.StringIO()) as terminal:
                        self.assertEqual(exporter.offline(source), 0)
                        self.assertEqual(exporter.offline(source), 1)
                    password_line = 'Password for WEB restore: '
                    self.assertEqual(terminal.getvalue().count(password_line), 1)
                    password = terminal.getvalue().partition(password_line)[2].splitlines()[0]
                    result = Path(directory) / output
                    self.assertEqual(exporter.decrypt_backup(result.read_bytes(), password), source.read_bytes())

    def test_malformed_xml_does_not_write_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'bad.xml'
            source.write_text('<DB, />', encoding='utf-8')
            with patch('builtins.input', side_effect=AssertionError('Unexpected prompt')):
                self.assertEqual(exporter.offline(source), 1)
            self.assertFalse(source.with_name('bad_repacked.cfg').exists())

    def test_cli_invalid_input_and_closed_stdin(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'example.cfg'
            for data, message, needs_password in (
                    (b'', 'Input file is empty', False),
                    (b'random text', 'Unrecognized file format', False),
                    (exporter.pack_web_backup(XML % b'test', PASSWORD), 'Input closed', True)):
                with self.subTest(message=message):
                    source.write_bytes(data)
                    result = subprocess.run([sys.executable, exporter.__file__, str(source)],
                                            stdin=subprocess.DEVNULL, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn(message, result.stderr)
                    self.assertNotIn('Traceback', result.stderr)
                    self.assertEqual('Backup password:' in result.stdout, needs_password)

    def test_native_database_with_xml_extension_still_uses_native_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            source = path / 'db_user_cfg.xml'
            source.write_bytes(struct.pack('>II', 0x01020304, 6))
            with patch('builtins.input', side_effect=['ZTEG00000000', '00:11:22:33:44:55']), \
                    patch.object(exporter, 'decrypt_internal_config', return_value=XML % b'native') as dec, \
                    patch.object(exporter, 'new_output_dir', return_value=path):
                self.assertEqual(exporter.offline(source), 0)
                dec.assert_called_once_with(source.read_bytes(), 'ZTEG00000000', '00:11:22:33:44:55')
            self.assertEqual((path / 'telnet_dbase.xml').read_bytes(), XML % b'native')


if __name__ == '__main__':
    unittest.main()
