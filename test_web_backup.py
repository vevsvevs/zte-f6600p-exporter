# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch
from xml.etree import ElementTree

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import zte_f6600p_export as exporter


PASSWORD = 'Example backup password'
PREFIX = b'Board S/N: 5A54454700000000\r\n'
CHUNK_SIZE = 128
XML = b'<DB><Tbl name="Example"><Row No="0"><DM name="Label" val="%s"/></Row></Tbl></DB>'


def cipher(password):
    key = hashlib.sha256(password.encode()).digest()
    iv = hashlib.sha256(b'ZTE%FN$GponNJ025').digest()[:16]
    return Cipher(algorithms.AES(key), modes.CBC(iv))


def make_template(xml, endian='>', pkcs7=False, flags=False):
    chunks, crc = bytearray(), 0
    for start in range(0, len(xml), CHUNK_SIZE):
        clear = xml[start:start + CHUNK_SIZE]
        compressed = zlib.compress(clear)
        last_chunk_offset = 60 + len(chunks)
        next_chunk = 0
        if start + len(clear) < len(xml):
            next_chunk = 1 if flags else last_chunk_offset + 12 + len(compressed)
        chunks.extend(struct.pack('>III', len(clear), len(compressed), next_chunk) + compressed)
        crc = zlib.crc32(compressed, crc)
    compressed_size = 60 + len(chunks) if flags else last_chunk_offset
    header = struct.pack('>6I', 0x01020304, 0, len(xml), compressed_size, CHUNK_SIZE, crc)
    inner = header + struct.pack('>I', zlib.crc32(header)) + bytes(32) + chunks
    pad_size = -len(inner) % 16
    padding = bytes([pad_size or 16]) * (pad_size or 16) if pkcs7 else bytes(pad_size)
    enc = cipher(PASSWORD).encryptor()
    ciphertext = enc.update(inner + padding) + enc.finalize()
    signed = struct.pack('>III', 0x04030201, 0, 7) + b'TestZTE'
    signed += struct.pack('>18I', 0x01020304, 6, len(inner), len(ciphertext) + 72,
                          *([0] * 11), len(inner), len(ciphertext), 0) + ciphertext
    outer = bytearray(bytes.fromhex('999999994444444455555555aaaaaaaa') + bytes(112))
    struct.pack_into(endian + 'I', outer, 24, 4)
    struct.pack_into(endian + 'II', outer, 68, 128, len(signed))
    return PREFIX + outer + signed


class WebBackupTest(unittest.TestCase):
    def test_rebuild_with_exact_multiple_of_chunk_size(self):
        edited = XML % (b'B' * (4 * CHUNK_SIZE - len(XML % b'')))
        for endian, pkcs7, flags in (('>', False, False), ('<', True, True)):
            with self.subTest(endian=endian):
                original = make_template(XML % (b'A' * 300), endian, pkcs7, flags)
                result = exporter.pack_web_backup(edited, original, PASSWORD)
                payload = len(PREFIX) + 128 + 12 + 7
                self.assertEqual(result[:len(PREFIX)], PREFIX)
                self.assertEqual(result[len(PREFIX) + 128:payload],
                                 original[len(PREFIX) + 128:payload])
                signed_size, = struct.unpack_from(endian + 'I', result, len(PREFIX) + 72)
                self.assertEqual(signed_size, len(result) - len(PREFIX) - 128)
                plain_size, cipher_size, following = struct.unpack_from('>III', result, payload + 60)
                self.assertEqual((cipher_size, following), (len(result) - payload - 72, 0))
                dec = cipher(PASSWORD).decryptor()
                inner = (dec.update(result[payload + 72:]) + dec.finalize())[:plain_size]
                header = struct.unpack_from('>15I', inner)
                self.assertEqual(header[6], zlib.crc32(inner[:24]))
                pos, crc, clear = 60, 0, bytearray()
                for index in range(4):
                    last_start = pos
                    n_plain, n_z, next_chunk = struct.unpack_from('>III', inner, pos)
                    compressed = inner[pos + 12:pos + 12 + n_z]
                    crc = zlib.crc32(compressed, crc)
                    clear.extend(zlib.decompress(compressed))
                    pos += 12 + n_z
                    self.assertEqual(n_plain, CHUNK_SIZE)
                    self.assertEqual(next_chunk, 0 if index == 3 else (1 if flags else pos))
                self.assertEqual((header[3], header[5], pos),
                                 (len(inner) if flags else last_start, crc, len(inner)))
                self.assertEqual(clear, edited)

    def test_invalid_xml_and_wrong_password(self):
        xml = XML % b'original'
        template = make_template(xml)
        for edited, error in ((b'<DB>', ElementTree.ParseError),
                              (b'<!DOCTYPE DB>' + xml, ValueError),
                              (xml.replace(b'name="Label"', b'name="Other"'), ValueError)):
            with self.subTest(error=error):
                with self.assertRaises(error):
                    exporter.pack_web_backup(edited, template, PASSWORD)
        with self.assertRaises(ValueError):
            exporter.pack_web_backup(xml, template, 'wrong password')

    def test_offline_xml_output_and_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            template = path / 'original.cfg'
            template.write_bytes(make_template(XML % b'old'))
            source = path / 'edited'
            source.write_bytes(b'\xef\xbb\xbf<!-- edited -->' + XML % b'new')
            with patch('builtins.input', return_value=str(template)), \
                    patch.object(exporter, 'getpass', return_value=PASSWORD):
                self.assertEqual(exporter.offline(source), 0)
                self.assertEqual(exporter.offline(source), 1)
            result = path / 'edited.repacked.cfg'
            self.assertEqual(exporter.decrypt_backup(result.read_bytes(), PASSWORD), source.read_bytes())

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
