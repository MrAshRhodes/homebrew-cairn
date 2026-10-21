"""Tests for scripts/bump_cask.py. They need no network and no real release."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import http.client
import io
import os
import plistlib
import posixpath
import re
import shutil
import subprocess
import sys
import unittest
import urllib.error
import urllib.parse
import zipfile
from pathlib import Path
from typing import Dict, List, Optional
from unittest import mock

from tests.support import FIXTURES, REPO_ROOT, ScratchTestCase, bump_cask, scratch_dir

BumpError = bump_cask.BumpError
REAL_CASK = (REPO_ROOT / "Casks" / "cairn.rb").read_text(encoding="utf-8")
GOOD_BANNER = "OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)"
SIGNED_OK = "Signature Verified Successfully"


def find_test_openssl() -> str:
    try:
        return bump_cask.find_openssl()
    except BumpError as exc:
        if os.environ.get("TAP_TESTS_REQUIRE_OPENSSL") == "1":
            raise AssertionError(f"OpenSSL >= 3 is required by these tests: {exc}") from exc
        raise unittest.SkipTest(f"OpenSSL >= 3 is not available: {exc}") from exc


def fake_openssl(
    directory: Path, name: str, banner: str, version_status: int = 0, verify_stdout: str = "", verify_status: int = 0
) -> str:
    """A shell script that answers `version` and anything else like a canned OpenSSL."""
    path = directory / name
    path.write_text(
        "#!/bin/sh\n"
        f"if [ \"$1\" = version ]; then echo '{banner}'; exit {version_status}; fi\n"
        f"echo '{verify_stdout}'\n"
        f"exit {verify_status}\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return str(path)


class Keypair:
    """A throwaway Ed25519 key pair made by the OpenSSL under test."""

    def __init__(self, openssl: str, directory: Path, name: str) -> None:
        self.openssl = openssl
        self.private = directory / f"{name}.pem"
        subprocess.run(
            [openssl, "genpkey", "-algorithm", "ED25519", "-out", str(self.private)], check=True, capture_output=True
        )
        der = subprocess.run(
            [openssl, "pkey", "-in", str(self.private), "-pubout", "-outform", "DER"], check=True, capture_output=True
        ).stdout
        if len(der) != 44 or der[:12] != bump_cask.ED25519_SPKI_PREFIX:
            raise AssertionError("unexpected Ed25519 public key encoding")
        self.public_b64 = base64.b64encode(der[12:]).decode("ascii")

    def sign_file(self, path: Path) -> str:
        signature = subprocess.run(
            [self.openssl, "pkeyutl", "-sign", "-rawin", "-inkey", str(self.private), "-in", str(path)],
            check=True,
            capture_output=True,
        ).stdout
        return base64.b64encode(signature).decode("ascii")


class OpenSSLTestCase(ScratchTestCase):
    """Skips (or, with TAP_TESTS_REQUIRE_OPENSSL=1, fails) unless a real OpenSSL >= 3 is available."""

    openssl: str
    pinned: Keypair
    other: Keypair

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.openssl = find_test_openssl()
        keys = scratch_dir()
        cls.addClassCleanup(shutil.rmtree, keys, ignore_errors=True)
        cls.pinned = Keypair(cls.openssl, keys, "pinned")
        cls.other = Keypair(cls.openssl, keys, "other")


# ---------------------------------------------------------------------------
# Builders for fake releases
# ---------------------------------------------------------------------------


def zip_bytes(members: Dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def app_zip(version: str, key_b64: str, **plist_overrides: object) -> bytes:
    plist: Dict[str, object] = {
        "CFBundleShortVersionString": version,
        "CFBundleIdentifier": bump_cask.BUNDLE_ID,
        "SUPublicEDKey": key_b64,
    }
    plist.update(plist_overrides)
    return zip_bytes({"Cairn.app/Contents/Info.plist": plistlib.dumps(plist), "Cairn.app/Contents/MacOS/Cairn": b"x"})


def appcast(version: str, length: int, signature: str, short_version: Optional[str] = None) -> bytes:
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        f'<rss xmlns:sparkle="{bump_cask.SPARKLE_NS}" version="2.0"><channel><item>\n'
        f"<sparkle:version>{version}</sparkle:version>\n"
        f"<sparkle:shortVersionString>{short_version or version}</sparkle:shortVersionString>\n"
        f'<enclosure url="https://github.com/mrashrhodes/cairn/releases/download/v{version}/Cairn-{version}-universal.zip"'
        f' length="{length}" type="application/octet-stream" sparkle:edSignature="{signature}"/>\n'
        "</item></channel></rss>\n"
    ).encode("utf-8")


class FakeRelease:
    """A release served from memory: the API object plus the ZIP, SHA256SUMS and appcast.xml files."""

    def __init__(
        self, scratch: Path, signer: Keypair, version: str, embedded_key: Optional[str] = None, **plist: object
    ) -> None:
        self.version = version
        self.zip_name = f"Cairn-{version}-universal.zip"
        data = app_zip(version, embedded_key or signer.public_b64, **plist)
        source = scratch / f"signed-{self.zip_name}"
        source.write_bytes(data)
        self.signature = signer.sign_file(source)
        self.files: Dict[str, bytes] = {}
        self.release: dict = {"draft": False, "prerelease": False, "tag_name": f"v{version}"}
        self.downloads: List[str] = []
        self.api_calls: List[tuple] = []
        self.set_zip(data)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.files[self.zip_name]).hexdigest()

    def set_zip(self, data: bytes) -> None:
        """Swap the ZIP and make every unauthenticated file agree with it; the signature stays as it was."""
        digest = hashlib.sha256(data).hexdigest()
        self.files[self.zip_name] = data
        self.files["SHA256SUMS"] = f"{digest}  ./{self.zip_name}\n".encode("utf-8")
        self.files["appcast.xml"] = appcast(self.version, len(data), self.signature)
        self.release["assets"] = [
            {"name": self.zip_name, "digest": f"sha256:{digest}"},
            {"name": "SHA256SUMS"},
            {"name": "appcast.xml"},
        ]

    def fetch_json(self, url: str, token: Optional[str]) -> dict:
        self.api_calls.append((url, token))
        return self.release

    def download(self, url: str, destination: Path, max_bytes: int) -> Path:
        self.downloads.append(url)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.files[posixpath.basename(urllib.parse.urlsplit(url).path)])
        return destination


# ---------------------------------------------------------------------------
# Versions, checksums, appcast
# ---------------------------------------------------------------------------


class VersionTests(unittest.TestCase):
    def test_parse_version(self) -> None:
        self.assertEqual(bump_cask.parse_version("0.1.0"), (0, 1, 0))
        self.assertEqual(bump_cask.parse_version("v12.0"), (12, 0))
        self.assertEqual(bump_cask.parse_version("1.2.3.4"), (1, 2, 3, 4))

    def test_parse_version_rejects_anything_else(self) -> None:
        for text in ("", "1", "v1", "1.2.3-beta1", "1.2.3+build", "1..2", ".1.2", "1.2.", "1.2.x", " 1.2", "1.2 ",
                     "1234567890.1", "V1.2", "latest"):  # fmt: skip
            with self.subTest(text=text), self.assertRaises(BumpError):
                bump_cask.parse_version(text)

    def test_compare_versions_is_numeric_and_pads_with_zeros(self) -> None:
        compare = bump_cask.compare_versions
        self.assertEqual(compare("0.1.0", "0.1.0"), 0)
        self.assertEqual(compare("0.1", "0.1.0"), 0)
        self.assertEqual(compare("0.2.0", "0.1.9"), 1)
        self.assertEqual(compare("0.9.0", "0.10.0"), -1)
        self.assertEqual(compare("1.0.0.1", "1.0.0"), 1)

    def test_version_from_tag_requires_a_v_prefix(self) -> None:
        self.assertEqual(bump_cask.version_from_tag("v0.1.0"), "0.1.0")
        for tag in ("0.1.0", "V0.1.0", "v1", "v1.2.3-rc1", "release-1.2", "vv1.2", ""):
            with self.subTest(tag=tag), self.assertRaises(BumpError):
                bump_cask.version_from_tag(tag)


class Sha256SumsTests(unittest.TestCase):
    def test_real_release_checksums(self) -> None:
        sums = bump_cask.parse_sha256sums((FIXTURES / "SHA256SUMS-0.1.0").read_text(encoding="utf-8"))
        self.assertEqual(
            sorted(sums),
            ["Cairn-0.1.0-universal.dmg", "Cairn-0.1.0-universal.zip", "RELEASE-INFO.json", "RELEASE-NOTES.txt", "appcast.xml"],
        )
        self.assertEqual(
            sums["Cairn-0.1.0-universal.zip"], "78009970464f5ce81441dffca80dbf9872cee261d0c1c9b8e07c140267f16cee"
        )

    def test_accepts_binary_marker_comments_blank_lines_and_crlf(self) -> None:
        digest = "a" * 64
        text = f"# comment\r\n\r\n{digest} *one.zip\r\n{digest.upper()}  ./two.zip\r\n"
        self.assertEqual(bump_cask.parse_sha256sums(text), {"one.zip": digest, "two.zip": digest})

    def test_rejects_malformed_lines(self) -> None:
        digest = "a" * 64
        for text in (
            f"nothex{'a' * 58}  file.zip\n",
            f"{digest} file.zip\n",
            f"{digest[:-1]}  file.zip\n",
            f"{digest}  \n",
            f"{digest}  ./\n",
            "just words\n",
        ):
            with self.subTest(text=text), self.assertRaises(BumpError):
                bump_cask.parse_sha256sums(text)

    def test_rejects_duplicate_names(self) -> None:
        digest = "a" * 64
        with self.assertRaisesRegex(BumpError, "more than once"):
            bump_cask.parse_sha256sums(f"{digest}  a.zip\n{'b' * 64}  ./a.zip\n")


def appcast_xml(*enclosures: str, short: str = "<sparkle:shortVersionString>0.1.0</sparkle:shortVersionString>") -> bytes:
    items = "".join(f"<item>{short}{enclosure}</item>" for enclosure in enclosures)
    return f'<rss xmlns:sparkle="{bump_cask.SPARKLE_NS}" version="2.0"><channel>{items}</channel></rss>'.encode("utf-8")


def enclosure_xml(url: str = "https://example.invalid/d/Cairn-0.1.0-universal.zip", attributes: str = "") -> str:
    return f'<enclosure url="{url}" {attributes}/>'


GOOD_ATTRIBUTES = 'length="10" sparkle:edSignature="c2ln"'
ASSET = "Cairn-0.1.0-universal.zip"


class AppcastTests(unittest.TestCase):
    def test_real_release_appcast(self) -> None:
        found = bump_cask.parse_appcast((FIXTURES / "appcast-0.1.0.xml").read_bytes(), ASSET)
        self.assertEqual(
            found.url, "https://github.com/mrashrhodes/cairn/releases/download/v0.1.0/Cairn-0.1.0-universal.zip"
        )
        self.assertEqual(found.length, 4150533)
        self.assertEqual(
            found.ed_signature,
            "rv+E/yXXk69YS0QU7bRvR8kXOHi5/BHFA+nUsdKvGNxg1xbU/DwsXcUiBCLV1iQJYrKYvw+C4yX2um63EFoUBA==",
        )
        self.assertEqual(found.short_version, "0.1.0")

    def test_matches_by_decoded_url_basename_and_ignores_the_query(self) -> None:
        for url in ("https://example.invalid/d/Cairn%2D0.1.0-universal.zip", f"https://example.invalid/d/{ASSET}?x=1"):
            with self.subTest(url=url):
                found = bump_cask.parse_appcast(appcast_xml(enclosure_xml(url, GOOD_ATTRIBUTES)), ASSET)
                self.assertEqual(found.ed_signature, "c2ln")

    def test_trims_the_signature_and_tolerates_a_missing_version(self) -> None:
        xml = appcast_xml(enclosure_xml(attributes='length="10" sparkle:edSignature=" c2ln "'), short="")
        found = bump_cask.parse_appcast(xml, ASSET)
        self.assertEqual(found.ed_signature, "c2ln")
        self.assertIsNone(found.short_version)

    def test_requires_exactly_one_enclosure_for_the_asset(self) -> None:
        other = enclosure_xml("https://example.invalid/d/other.zip", GOOD_ATTRIBUTES)
        with self.assertRaisesRegex(BumpError, "found 0"):
            bump_cask.parse_appcast(appcast_xml(other), ASSET)
        twice = enclosure_xml(attributes=GOOD_ATTRIBUTES)
        with self.assertRaisesRegex(BumpError, "found 2"):
            bump_cask.parse_appcast(appcast_xml(twice, twice), ASSET)

    def test_requires_a_namespaced_signature_and_a_numeric_length(self) -> None:
        cases = {
            "no signature": 'length="10"',
            "unprefixed signature": 'length="10" edSignature="c2ln"',
            "no length": 'sparkle:edSignature="c2ln"',
            "bad length": 'length="ten" sparkle:edSignature="c2ln"',
        }
        for label, attributes in cases.items():
            with self.subTest(label), self.assertRaises(BumpError):
                bump_cask.parse_appcast(appcast_xml(enclosure_xml(attributes=attributes)), ASSET)

    def test_rejects_dtds_bad_xml_and_bad_encoding(self) -> None:
        with self.assertRaisesRegex(BumpError, "DOCTYPE or ENTITY"):
            bump_cask.parse_appcast(b'<!DOCTYPE rss [<!ENTITY x "y">]><rss/>', ASSET)
        with self.assertRaisesRegex(BumpError, "DOCTYPE or ENTITY"):
            bump_cask.parse_appcast(b'<?xml version="1.0"?><! doctype rss><rss/>', ASSET)
        with self.assertRaisesRegex(BumpError, "not well-formed"):
            bump_cask.parse_appcast(b"<rss>", ASSET)
        with self.assertRaisesRegex(BumpError, "UTF-8"):
            bump_cask.parse_appcast(b"\xff\xfe<rss/>", ASSET)


# ---------------------------------------------------------------------------
# Keys, OpenSSL, signatures
# ---------------------------------------------------------------------------


class PinnedKeyTests(ScratchTestCase):
    def write_key(self, data: bytes) -> Path:
        path = self.tmp / "key.txt"
        path.write_bytes(data)
        return path

    def test_reads_and_strips_the_key(self) -> None:
        key = base64.b64encode(bytes(range(32))).decode("ascii")
        self.assertEqual(bump_cask.read_pinned_key(self.write_key(f"{key}\n".encode())), key)

    def test_rejects_bad_key_files(self) -> None:
        cases = {
            "not base64": b"not base64!!",
            "empty": b"",
            "31 bytes": base64.b64encode(bytes(31)),
            "33 bytes": base64.b64encode(bytes(33)),
            "not ASCII": b"\xff\xfe",
        }
        for label, data in cases.items():
            with self.subTest(label), self.assertRaises(BumpError):
                bump_cask.read_pinned_key(self.write_key(data))
        with self.assertRaisesRegex(BumpError, "cannot read pinned public key"):
            bump_cask.read_pinned_key(self.tmp / "missing.txt")

    def test_decode_base64_is_strict(self) -> None:
        self.assertEqual(bump_cask.decode_base64("AAAA", 3, "x"), bytes(3))
        for text in ("AA AA", "AA-_", "AAA", "AAAA\nAAAA"):
            with self.subTest(text=text), self.assertRaises(BumpError):
                bump_cask.decode_base64(text, 3, "x")
        with self.assertRaisesRegex(BumpError, "must be 4 bytes, got 3"):
            bump_cask.decode_base64("AAAA", 4, "x")

    def test_pem_wraps_the_raw_key_in_a_subject_public_key_info(self) -> None:
        raw = bytes(range(32))
        pem = bump_cask.public_key_pem(base64.b64encode(raw).decode("ascii"))
        lines = pem.splitlines()
        self.assertEqual((lines[0], lines[-1]), ("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"))
        self.assertEqual(base64.b64decode("".join(lines[1:-1])), bytes.fromhex("302a300506032b6570032100") + raw)
        self.assertTrue(pem.endswith("\n"))


class OpenSSLDiscoveryTests(ScratchTestCase):
    def test_accepts_openssl_3_and_reports_its_version(self) -> None:
        self.assertEqual(bump_cask.openssl_version(fake_openssl(self.tmp, "ok", GOOD_BANNER)), (3, 0, 13))

    def test_rejects_libressl_old_openssl_failures_and_missing_binaries(self) -> None:
        cases = {
            "LibreSSL": fake_openssl(self.tmp, "libre", "LibreSSL 3.3.6"),
            "OpenSSL 1.1": fake_openssl(self.tmp, "old", "OpenSSL 1.1.1w  11 Sep 2023"),
            "failing": fake_openssl(self.tmp, "failing", GOOD_BANNER, version_status=1),
            "missing": str(self.tmp / "nowhere" / "openssl"),
        }
        for label, path in cases.items():
            with self.subTest(label), self.assertRaises(BumpError):
                bump_cask.openssl_version(path)
        with self.assertRaisesRegex(BumpError, "LibreSSL cannot verify"):
            bump_cask.openssl_version(cases["LibreSSL"])

    def test_an_explicit_choice_must_itself_be_usable(self) -> None:
        good = fake_openssl(self.tmp, "ok", GOOD_BANNER)
        self.assertEqual(bump_cask.find_openssl(good), good)
        with self.assertRaises(BumpError):
            bump_cask.find_openssl(fake_openssl(self.tmp, "libre", "LibreSSL 3.3.6"))

    def test_search_skips_unusable_candidates(self) -> None:
        libre = fake_openssl(self.tmp, "libre", "LibreSSL 3.3.6")
        good = fake_openssl(self.tmp, "ok", GOOD_BANNER)
        with mock.patch.dict(os.environ, {"OPENSSL": libre}), mock.patch.object(bump_cask.shutil, "which", return_value=good):
            self.assertEqual(bump_cask.find_openssl(), good)
        with mock.patch.dict(os.environ, {"OPENSSL": good}), mock.patch.object(bump_cask.shutil, "which", return_value=libre):
            self.assertEqual(bump_cask.find_openssl(), good)

    def test_search_reports_when_nothing_is_usable(self) -> None:
        libre = fake_openssl(self.tmp, "libre", "LibreSSL 3.3.6")
        with (
            mock.patch.dict(os.environ, {"OPENSSL": libre}),
            mock.patch.object(bump_cask.shutil, "which", return_value=libre),
            mock.patch.object(bump_cask, "_OPENSSL_FALLBACKS", ()),
            self.assertRaisesRegex(BumpError, "no OpenSSL >= 3.0 found"),
        ):
            bump_cask.find_openssl()


class VerifyEd25519WithoutRealOpenSSLTests(ScratchTestCase):
    """The success phrase and exit status must both be right; a silent OpenSSL never counts as a pass."""

    KEY = base64.b64encode(bytes(32)).decode("ascii")
    SIGNATURE = base64.b64encode(bytes(64)).decode("ascii")

    def verify(self, openssl: str) -> None:
        data = self.tmp / "data.bin"
        data.write_bytes(b"data")
        bump_cask.verify_ed25519(openssl, self.KEY, self.SIGNATURE, data, self.tmp / "work")

    def test_rejects_libressl_before_doing_anything(self) -> None:
        with self.assertRaisesRegex(BumpError, "LibreSSL cannot verify"):
            self.verify(fake_openssl(self.tmp, "libre", "LibreSSL 3.3.6"))

    def test_zero_exit_without_the_success_phrase_is_a_failure(self) -> None:
        with self.assertRaisesRegex(BumpError, "did not verify"):
            self.verify(fake_openssl(self.tmp, "quiet", GOOD_BANNER))

    def test_the_success_phrase_with_a_failing_exit_is_a_failure(self) -> None:
        with self.assertRaisesRegex(BumpError, "did not verify"):
            self.verify(fake_openssl(self.tmp, "odd", GOOD_BANNER, verify_stdout=SIGNED_OK, verify_status=1))

    def test_the_success_phrase_with_a_zero_exit_is_a_pass(self) -> None:
        self.verify(fake_openssl(self.tmp, "fine", GOOD_BANNER, verify_stdout=SIGNED_OK))


class Ed25519Tests(OpenSSLTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.data = self.tmp / "data.bin"
        self.data.write_bytes(b"release bytes " * 4096)
        self.work = self.tmp / "work"
        self.signature = self.pinned.sign_file(self.data)

    def verify(self, key: Optional[str] = None, signature: Optional[str] = None) -> None:
        bump_cask.verify_ed25519(
            self.openssl, key or self.pinned.public_b64, signature or self.signature, self.data, self.work
        )

    def test_accepts_a_valid_signature(self) -> None:
        self.verify()
        self.assertEqual((self.work / "sparkle-public-key.pem").read_text(), bump_cask.public_key_pem(self.pinned.public_b64))
        self.assertEqual((self.work / "signature.bin").read_bytes(), base64.b64decode(self.signature))

    def test_rejects_modified_data(self) -> None:
        self.data.write_bytes(self.data.read_bytes() + b"!")
        with self.assertRaisesRegex(BumpError, "did not verify"):
            self.verify()

    def test_rejects_any_flipped_signature_byte(self) -> None:
        for index in (0, 31, 32, 63):
            raw = bytearray(base64.b64decode(self.signature))
            raw[index] ^= 0x01
            with self.subTest(index=index), self.assertRaisesRegex(BumpError, "did not verify"):
                self.verify(signature=base64.b64encode(bytes(raw)).decode("ascii"))

    def test_rejects_a_signature_from_another_key(self) -> None:
        with self.assertRaisesRegex(BumpError, "did not verify"):
            self.verify(signature=self.other.sign_file(self.data))

    def test_rejects_a_different_public_key(self) -> None:
        with self.assertRaisesRegex(BumpError, "did not verify"):
            self.verify(key=self.other.public_b64)

    def test_rejects_malformed_keys_and_signatures(self) -> None:
        def b64(size: int) -> str:
            return base64.b64encode(bytes(size)).decode("ascii")

        cases = [
            ("signature not base64", None, "***not base64***", "not valid base64"),
            ("key not base64", "***not base64***", None, "not valid base64"),
            ("signature too short", None, b64(63), "must be 64 bytes"),
            ("signature too long", None, b64(65), "must be 64 bytes"),
            ("key too short", b64(31), None, "must be 32 bytes"),
            ("key too long", b64(33), None, "must be 32 bytes"),
        ]
        for label, key, signature, message in cases:
            with self.subTest(label), self.assertRaisesRegex(BumpError, message):
                self.verify(key=key, signature=signature)

    def test_pem_is_what_openssl_itself_writes(self) -> None:
        written = subprocess.run(
            [self.openssl, "pkey", "-in", str(self.pinned.private), "-pubout"], check=True, capture_output=True, text=True
        ).stdout
        self.assertEqual(bump_cask.public_key_pem(self.pinned.public_b64), written)


# ---------------------------------------------------------------------------
# The downloaded ZIP
# ---------------------------------------------------------------------------


class AppBundleTests(ScratchTestCase):
    KEY = base64.b64encode(bytes(range(32))).decode("ascii")
    MEMBER = "Cairn.app/Contents/Info.plist"

    def write(self, data: bytes) -> Path:
        path = self.tmp / "Cairn.zip"
        path.write_bytes(data)
        return path

    def test_accepts_the_expected_bundle(self) -> None:
        bump_cask.check_app_bundle(self.write(app_zip("1.2.3", self.KEY)), "1.2.3", self.KEY)

    def test_rejects_a_different_version_identifier_or_key(self) -> None:
        without_key = plistlib.dumps({"CFBundleShortVersionString": "1.2.3", "CFBundleIdentifier": bump_cask.BUNDLE_ID})
        cases = {
            "version": (app_zip("1.2.3", self.KEY, CFBundleShortVersionString="1.2.2"), "CFBundleShortVersionString"),
            "identifier": (app_zip("1.2.3", self.KEY, CFBundleIdentifier="com.example.other"), "CFBundleIdentifier"),
            "key": (app_zip("1.2.3", base64.b64encode(bytes(32)).decode("ascii")), "SUPublicEDKey"),
            "no key": (zip_bytes({self.MEMBER: without_key}), "SUPublicEDKey"),
        }
        for label, (data, field) in cases.items():
            with self.subTest(label), self.assertRaisesRegex(BumpError, field):
                bump_cask.check_app_bundle(self.write(data), "1.2.3", self.KEY)

    def test_rejects_archives_without_a_usable_info_plist(self) -> None:
        cases = {
            "no plist": (zip_bytes({"Cairn.app/Contents/MacOS/Cairn": b"x"}), "contains no"),
            "not a zip": (b"this is not a zip", "not a valid ZIP"),
            "garbage plist": (zip_bytes({self.MEMBER: b"not a plist"}), "not a valid property list"),
            "huge plist": (zip_bytes({self.MEMBER: plistlib.dumps({"x": "a" * (1024 * 1024 + 1)})}), "unexpectedly large"),
            "plist is a list": (zip_bytes({self.MEMBER: plistlib.dumps(["a"])}), "CFBundleShortVersionString"),
            "wrong app name": (zip_bytes({"Other.app/Contents/Info.plist": plistlib.dumps({})}), "contains no"),
        }
        for label, (data, message) in cases.items():
            with self.subTest(label), self.assertRaisesRegex(BumpError, message):
                bump_cask.check_app_bundle(self.write(data), "1.2.3", self.KEY)

    def test_sha256_file_matches_hashlib(self) -> None:
        path = self.write(b"abc" * 1_000_000)
        self.assertEqual(bump_cask.sha256_file(path), hashlib.sha256(b"abc" * 1_000_000).hexdigest())


# ---------------------------------------------------------------------------
# Cask editing
# ---------------------------------------------------------------------------

TEMPLATE = """cask "cairn" do
  version "0.1.0"
  sha256 "@SHA@"

  url "https://github.com/MrAshRhodes/cairn/releases/download/v#{version}/Cairn-#{version}-universal.zip"

  livecheck do
    version "4.4.4"
    sha256 "@OTHER@"
  end
end
""".replace("@SHA@", "a" * 64).replace("@OTHER@", "b" * 64)


class CaskEditingTests(ScratchTestCase):
    def test_reads_the_values_the_script_edits(self) -> None:
        self.assertEqual(bump_cask.cask_version(TEMPLATE), "0.1.0")
        self.assertEqual(bump_cask.cask_sha256(TEMPLATE), "a" * 64)
        self.assertEqual(
            bump_cask.cask_url(TEMPLATE, "9.9.9"),
            "https://github.com/MrAshRhodes/cairn/releases/download/v9.9.9/Cairn-9.9.9-universal.zip",
        )
        self.assertEqual(bump_cask.cask_version('  version "1.0"  \t\n'), "1.0")

    def test_rewrite_changes_only_the_two_top_level_lines(self) -> None:
        updated = bump_cask.rewrite_cask(TEMPLATE, "0.2.0", "c" * 64)
        before, after = TEMPLATE.splitlines(), updated.splitlines()
        self.assertEqual(len(before), len(after))
        changed = [(old, new) for old, new in zip(before, after) if old != new]
        self.assertEqual(changed, [('  version "0.1.0"', '  version "0.2.0"'), (f'  sha256 "{"a" * 64}"', f'  sha256 "{"c" * 64}"')])
        self.assertIn('    version "4.4.4"', updated)
        self.assertIn(f'    sha256 "{"b" * 64}"', updated)
        self.assertEqual(updated.endswith("\n"), TEMPLATE.endswith("\n"))

    def test_rewriting_with_the_current_values_changes_nothing(self) -> None:
        self.assertEqual(bump_cask.rewrite_cask(TEMPLATE, "0.1.0", "a" * 64), TEMPLATE)

    def test_the_real_cask_can_be_rewritten_and_only_two_lines_differ(self) -> None:
        updated = bump_cask.rewrite_cask(REAL_CASK, "9.8.7", "ab" * 32)
        differing = [(a, b) for a, b in zip(REAL_CASK.splitlines(), updated.splitlines()) if a != b]
        self.assertEqual(len(REAL_CASK.splitlines()), len(updated.splitlines()))
        self.assertEqual([new for _, new in differing], ['  version "9.8.7"', f'  sha256 "{"ab" * 32}"'])

    def test_rewrite_refuses_ambiguous_or_unexpected_casks(self) -> None:
        cases = {
            "duplicate version": TEMPLATE.replace('  version "0.1.0"\n', '  version "0.1.0"\n  version "0.1.0"\n'),
            "no version": TEMPLATE.replace('  version "0.1.0"\n', ""),
            "duplicate sha256": TEMPLATE.replace("\n\n  url", f'\n  sha256 "{"a" * 64}"\n\n  url'),
            "no sha256": TEMPLATE.replace(f'  sha256 "{"a" * 64}"\n', ""),
            "two urls": TEMPLATE.replace("\n\n  livecheck", '\n  url "https://example.invalid/#{version}"\n\n  livecheck'),
            "version-less url": TEMPLATE.replace("v#{version}/Cairn-#{version}", "latest/Cairn"),
            "no url": TEMPLATE.replace('  url "https://github.com/MrAshRhodes/cairn/releases/download/v#{version}/Cairn-#{version}-universal.zip"\n', ""),
        }  # fmt: skip
        for label, text in cases.items():
            with self.subTest(label), self.assertRaises(BumpError):
                bump_cask.rewrite_cask(text, "0.2.0", "c" * 64)

    def test_rewrite_checks_the_new_values(self) -> None:
        for version in ("v0.2.0", "0.2.0-beta", "2", "", "latest"):
            with self.subTest(version=version), self.assertRaises(BumpError):
                bump_cask.rewrite_cask(TEMPLATE, version, "c" * 64)
        for digest in ("C" * 64, "c" * 63, "c" * 65, "sha256:" + "c" * 64, "", "g" * 64):
            with self.subTest(digest=digest), self.assertRaises(BumpError):
                bump_cask.rewrite_cask(TEMPLATE, "0.2.0", digest)
        self.assertIn('  version "0.2"\n', bump_cask.rewrite_cask(TEMPLATE, "0.2", "c" * 64))

    def test_write_text_atomic_replaces_the_file_and_leaves_no_partial_file(self) -> None:
        target = self.tmp / "cairn.rb"
        target.write_text("old", encoding="utf-8")
        bump_cask.write_text_atomic(target, "new\n")
        self.assertEqual(target.read_text(encoding="utf-8"), "new\n")
        self.assertEqual(sorted(path.name for path in self.tmp.iterdir()), ["cairn.rb"])


# ---------------------------------------------------------------------------
# Network helpers (everything is mocked)
# ---------------------------------------------------------------------------


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://example.invalid/x", code, "status", {}, io.BytesIO(b""))  # type: ignore[arg-type]


class RetryTests(unittest.TestCase):
    def test_client_errors_are_not_retried(self) -> None:
        calls: List[int] = []

        def action() -> None:
            calls.append(1)
            raise http_error(404)

        with mock.patch.object(bump_cask.time, "sleep") as sleep, self.assertRaisesRegex(BumpError, "HTTP 404"):
            bump_cask._retrying("https://example.invalid/x", action)
        self.assertEqual(len(calls), 1)
        sleep.assert_not_called()

    def test_server_errors_are_retried_and_then_reported(self) -> None:
        calls: List[int] = []

        def action() -> None:
            calls.append(1)
            raise http_error(503)

        with (
            mock.patch.object(bump_cask.time, "sleep") as sleep,
            self.assertRaisesRegex(BumpError, "giving up on .* after 3 attempts"),
        ):
            bump_cask._retrying("https://example.invalid/x", action)
        self.assertEqual(len(calls), 3)
        self.assertEqual(sleep.call_args_list, [mock.call(2), mock.call(4)])

    def test_rate_limits_and_dropped_connections_are_retried(self) -> None:
        outcomes: list = [http_error(429), ConnectionResetError("reset"), http.client.IncompleteRead(b""), "fine"]

        def action() -> str:
            outcome = outcomes.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

        with mock.patch.object(bump_cask.time, "sleep"):
            self.assertEqual(bump_cask._retrying("https://example.invalid/x", action, attempts=4), "fine")


class OpenTests(unittest.TestCase):
    def test_refuses_anything_but_https(self) -> None:
        for url in ("http://example.invalid/x", "file:///etc/passwd", "ftp://example.invalid/x"):
            with self.subTest(url=url), self.assertRaisesRegex(BumpError, "non-HTTPS"):
                bump_cask._open(url, None, None)

    def test_the_token_only_goes_to_the_api_host(self) -> None:
        with mock.patch.object(bump_cask.urllib.request, "urlopen") as urlopen:
            bump_cask._open("https://api.github.com/repos/o/r/releases/latest", "tok", "application/json")
            api_request = urlopen.call_args[0][0]
            bump_cask._open("https://github.com/o/r/releases/download/v1/x.zip", "tok", None)
            download_request = urlopen.call_args[0][0]
            bump_cask._open("https://objects.githubusercontent.com/x", "tok", None)
            redirect_request = urlopen.call_args[0][0]
        self.assertEqual(api_request.get_header("Authorization"), "Bearer tok")
        self.assertEqual(api_request.get_header("Accept"), "application/json")
        self.assertFalse(download_request.has_header("Authorization"))
        self.assertFalse(redirect_request.has_header("Authorization"))
        self.assertTrue(download_request.get_header("User-agent").startswith("homebrew-cairn-bump"))

    def test_no_token_means_no_authorization_header(self) -> None:
        with mock.patch.object(bump_cask.urllib.request, "urlopen") as urlopen:
            bump_cask._open("https://api.github.com/x", None, None)
        self.assertFalse(urlopen.call_args[0][0].has_header("Authorization"))


class FetchAndDownloadTests(ScratchTestCase):
    def test_fetch_json_decodes_and_reports_bad_json(self) -> None:
        with mock.patch.object(bump_cask, "_open", return_value=io.BytesIO(b'{"a": 1}')):
            self.assertEqual(bump_cask.fetch_json("https://api.github.com/x", None), {"a": 1})
        with mock.patch.object(bump_cask, "_open", return_value=io.BytesIO(b"<html>")):
            with self.assertRaisesRegex(BumpError, "did not return valid JSON"):
                bump_cask.fetch_json("https://api.github.com/x", None)

    def test_fetch_json_enforces_a_size_limit(self) -> None:
        with (
            mock.patch.object(bump_cask, "MAX_JSON_BYTES", 8),
            mock.patch.object(bump_cask, "_open", return_value=io.BytesIO(b'{"a": "0123456789"}')),
            self.assertRaisesRegex(BumpError, "too large"),
        ):
            bump_cask.fetch_json("https://api.github.com/x", None)

    def test_download_writes_the_file_through_a_partial_file(self) -> None:
        destination = self.tmp / "nested" / "file.bin"
        with mock.patch.object(bump_cask, "_open", side_effect=lambda *a: io.BytesIO(b"x" * 100)):
            self.assertEqual(bump_cask.download("https://example.invalid/f", destination, 1000), destination)
        self.assertEqual(destination.read_bytes(), b"x" * 100)
        self.assertEqual([path.name for path in destination.parent.iterdir()], ["file.bin"])

    def test_download_enforces_a_size_limit_and_cleans_up(self) -> None:
        destination = self.tmp / "big.bin"
        with (
            mock.patch.object(bump_cask, "_open", side_effect=lambda *a: io.BytesIO(b"x" * 100)),
            self.assertRaisesRegex(BumpError, "larger than 50 bytes"),
        ):
            bump_cask.download("https://example.invalid/f", destination, 50)
        self.assertEqual(list(self.tmp.iterdir()), [])


class LatestReleaseTests(unittest.TestCase):
    def test_accepts_a_published_release(self) -> None:
        release = {"draft": False, "prerelease": False, "tag_name": "v0.2.0"}
        self.assertEqual(bump_cask.latest_release_version(release), "0.2.0")

    def test_rejects_unexpected_or_unpublished_releases(self) -> None:
        cases = [
            [],
            None,
            {"draft": True, "prerelease": False, "tag_name": "v0.2.0"},
            {"draft": False, "prerelease": True, "tag_name": "v0.2.0"},
            {"prerelease": False, "tag_name": "v0.2.0"},
            {"draft": False, "tag_name": "v0.2.0"},
            {"draft": False, "prerelease": False},
            {"draft": False, "prerelease": False, "tag_name": 2},
            {"draft": False, "prerelease": False, "tag_name": "0.2.0"},
        ]
        for release in cases:
            with self.subTest(release=release), self.assertRaises(BumpError):
                bump_cask.latest_release_version(release)


class ActionsPlumbingTests(ScratchTestCase):
    def test_outputs_are_appended_when_github_output_is_set(self) -> None:
        path = self.tmp / "out.txt"
        path.write_text("earlier=1\n", encoding="utf-8")
        os.environ["GITHUB_OUTPUT"] = str(path)
        bump_cask.write_outputs(changed="true", version="0.2.0")
        self.assertEqual(path.read_text(encoding="utf-8"), "earlier=1\nchanged=true\nversion=0.2.0\n")

    def test_outputs_are_skipped_outside_actions(self) -> None:
        bump_cask.write_outputs(changed="true")
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_multi_line_output_values_are_refused(self) -> None:
        os.environ["GITHUB_OUTPUT"] = str(self.tmp / "out.txt")
        for value in ("a\nb", "a\rb"):
            with self.subTest(value=value), self.assertRaisesRegex(BumpError, "multi-line"):
                bump_cask.write_outputs(version=value)

    def test_summary_is_appended_when_requested(self) -> None:
        bump_cask.write_summary("ignored")
        path = self.tmp / "summary.md"
        os.environ["GITHUB_STEP_SUMMARY"] = str(path)
        bump_cask.write_summary("### Title\n\n")
        bump_cask.write_summary("more")
        self.assertEqual(path.read_text(encoding="utf-8"), "### Title\nmore\n")

    def test_annotations_escape_control_characters(self) -> None:
        self.assertEqual(bump_cask._annotation("50% done\r\nnext"), "50%25 done%0D%0Anext")


class CommandLineTests(unittest.TestCase):
    def test_defaults(self) -> None:
        args = bump_cask.parse_args([])
        self.assertEqual((args.repo, args.cask, args.pubkey), ("MrAshRhodes/cairn", "Casks/cairn.rb", "keys/sparkle-public-ed-key.txt"))
        self.assertFalse(args.dry_run or args.verify_current)

    def test_script_runs_as_a_program(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "bump_cask.py"), "--help"], capture_output=True, text=True, check=False
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--dry-run", proc.stdout)
        self.assertIn("--verify-current", proc.stdout)


# ---------------------------------------------------------------------------
# End to end: run() against fake releases
# ---------------------------------------------------------------------------


class RunTests(OpenSSLTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.cask = self.tmp / "Casks" / "cairn.rb"
        self.cask.parent.mkdir()
        self.original = bump_cask.rewrite_cask(REAL_CASK, "0.1.0", "0" * 64)
        self.cask.write_text(self.original, encoding="utf-8")
        self.pubkey = self.tmp / "pinned-key.txt"
        self.pubkey.write_text(self.pinned.public_b64 + "\n", encoding="ascii")
        self.workdir = self.tmp / "work"
        self.output = self.tmp / "github-output.txt"
        os.environ["GITHUB_OUTPUT"] = str(self.output)

    def release(self, version: str, signer: Optional[Keypair] = None, **kwargs: object) -> FakeRelease:
        return FakeRelease(self.tmp, signer or self.pinned, version, **kwargs)  # type: ignore[arg-type]

    def argv(self, *flags: str, openssl: Optional[str] = None) -> List[str]:
        return [
            "--cask", str(self.cask), "--pubkey", str(self.pubkey), "--workdir", str(self.workdir),
            "--openssl", openssl or self.openssl, *flags,
        ]  # fmt: skip

    @contextlib.contextmanager
    def serving(self, release: FakeRelease):
        with (
            mock.patch.object(bump_cask, "fetch_json", release.fetch_json),
            mock.patch.object(bump_cask, "download", release.download),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            yield out

    def bump(self, release: FakeRelease, *flags: str, openssl: Optional[str] = None) -> str:
        args = bump_cask.parse_args(self.argv(*flags, openssl=openssl))
        with self.serving(release) as out:
            self.assertEqual(bump_cask.run(args), 0)
        return out.getvalue()

    def outputs(self) -> Dict[str, str]:
        if not self.output.exists():
            return {}
        return dict(line.split("=", 1) for line in self.output.read_text(encoding="utf-8").splitlines())

    def test_a_newer_verified_release_updates_the_cask(self) -> None:
        release = self.release("0.2.0")
        log = self.bump(release)
        self.assertEqual(self.cask.read_text(encoding="utf-8"), bump_cask.rewrite_cask(self.original, "0.2.0", release.sha256))
        self.assertEqual(self.outputs(), {"changed": "true", "version": "0.2.0", "sha256": release.sha256})
        self.assertIn("ok: Sparkle Ed25519 signature", log)
        self.assertEqual(len(release.downloads), 3)
        self.assertEqual(
            release.downloads[0], "https://github.com/MrAshRhodes/cairn/releases/download/v0.2.0/Cairn-0.2.0-universal.zip"
        )

    def test_a_dry_run_verifies_but_does_not_touch_the_cask(self) -> None:
        log = self.bump(self.release("0.2.0"), "--dry-run")
        self.assertEqual(self.cask.read_text(encoding="utf-8"), self.original)
        self.assertEqual(self.outputs(), {"changed": "false", "version": "0.1.0"})
        self.assertIn("Dry run: would bump 0.1.0 -> 0.2.0", log)

    def test_a_dry_run_still_rejects_a_bad_release(self) -> None:
        release = self.release("0.2.0", signer=self.other, embedded_key=self.pinned.public_b64)
        with self.assertRaisesRegex(BumpError, "did not verify"):
            self.bump(release, "--dry-run")

    def test_an_up_to_date_cask_downloads_nothing(self) -> None:
        release = self.release("0.1.0")
        log = self.bump(release)
        self.assertEqual(release.downloads, [])
        self.assertEqual(self.cask.read_text(encoding="utf-8"), self.original)
        self.assertEqual(self.outputs(), {"changed": "false", "version": "0.1.0"})
        self.assertIn("Cask is up to date (0.1.0); nothing to do.", log)

    def test_verify_current_checks_the_release_the_cask_pins(self) -> None:
        release = self.release("0.2.0")
        pinned = bump_cask.rewrite_cask(self.original, "0.2.0", release.sha256)
        self.cask.write_text(pinned, encoding="utf-8")
        log = self.bump(release, "--verify-current")
        self.assertEqual(len(release.downloads), 3)
        self.assertEqual(self.cask.read_text(encoding="utf-8"), pinned)
        self.assertEqual(self.outputs(), {"changed": "false", "version": "0.2.0"})
        self.assertIn("verified; the cask is correct", log)

    def test_verify_current_catches_a_wrong_pinned_sha256(self) -> None:
        release = self.release("0.2.0")
        self.cask.write_text(bump_cask.rewrite_cask(self.original, "0.2.0", "1" * 64), encoding="utf-8")
        with self.assertRaisesRegex(BumpError, "the cask pins sha256"):
            self.bump(release, "--verify-current")

    def test_an_older_release_is_never_a_downgrade(self) -> None:
        release = self.release("0.0.9")
        log = self.bump(release)
        self.assertEqual(release.downloads, [])
        self.assertEqual(self.cask.read_text(encoding="utf-8"), self.original)
        self.assertEqual(self.outputs(), {"changed": "false", "version": "0.1.0"})
        self.assertIn("not downgrading", log)
        self.assertNotIn("::warning::", log)

    def test_the_downgrade_notice_is_a_warning_annotation_in_actions(self) -> None:
        os.environ["GITHUB_ACTIONS"] = "true"
        self.assertIn("::warning::Latest release v0.0.9 is older", self.bump(self.release("0.0.9")))

    def test_the_api_call_uses_the_actions_token(self) -> None:
        release = self.release("0.1.0")
        os.environ["GH_TOKEN"] = "from-gh-token"
        self.bump(release)
        os.environ["GITHUB_TOKEN"] = "from-github-token"
        self.bump(release)
        url = "https://api.github.com/repos/MrAshRhodes/cairn/releases/latest"
        self.assertEqual(release.api_calls, [(url, "from-gh-token"), (url, "from-github-token")])

    def test_the_repository_name_is_compared_case_insensitively(self) -> None:
        self.bump(self.release("0.2.0"), "--repo", "mrashrhodes/cairn")
        self.assertEqual(bump_cask.cask_version(self.cask.read_text(encoding="utf-8")), "0.2.0")

    def test_a_cask_url_for_another_repository_is_refused(self) -> None:
        release = self.release("0.2.0")
        with self.assertRaisesRegex(BumpError, "the cask url resolves to"):
            self.bump(release, "--repo", "someone/else")
        self.assertEqual(release.downloads, [])

    def test_a_bad_pinned_key_file_is_refused(self) -> None:
        self.pubkey.write_text("not a key\n", encoding="ascii")
        with self.assertRaisesRegex(BumpError, "pinned public key"):
            self.bump(self.release("0.2.0"))

    def test_libressl_is_refused(self) -> None:
        libre = fake_openssl(self.tmp, "libre", "LibreSSL 3.3.6")
        with self.assertRaisesRegex(BumpError, "LibreSSL cannot verify"):
            self.bump(self.release("0.2.0"), openssl=libre)

    def test_every_failed_check_leaves_the_cask_untouched(self) -> None:
        def mutate(change):
            def build() -> FakeRelease:
                release = self.release("0.2.0")
                change(release)
                return release

            return build

        def wrong_sums(release: FakeRelease) -> None:
            release.files["SHA256SUMS"] = f"{'0' * 64}  ./{release.zip_name}\n".encode()

        def no_sums_entry(release: FakeRelease) -> None:
            release.files["SHA256SUMS"] = f"{'0' * 64}  ./other.zip\n".encode()

        def wrong_digest(release: FakeRelease) -> None:
            release.release["assets"][0]["digest"] = "sha256:" + "1" * 64

        def wrong_length(release: FakeRelease) -> None:
            release.files["appcast.xml"] = appcast("0.2.0", len(release.files[release.zip_name]) + 1, release.signature)

        def wrong_item_version(release: FakeRelease) -> None:
            release.files["appcast.xml"] = appcast(
                "0.2.0", len(release.files[release.zip_name]), release.signature, short_version="0.2.1"
            )

        def unsigned(release: FakeRelease) -> None:
            release.files["appcast.xml"] = release.files["appcast.xml"].replace(b"sparkle:edSignature", b"unknown")

        def with_dtd(release: FakeRelease) -> None:
            release.files["appcast.xml"] = b'<!DOCTYPE rss [<!ENTITY x "y">]>' + release.files["appcast.xml"]

        def swapped_zip(release: FakeRelease) -> None:
            release.set_zip(release.files[release.zip_name] + b"tampered")

        def draft(release: FakeRelease) -> None:
            release.release["draft"] = True

        def prerelease(release: FakeRelease) -> None:
            release.release["prerelease"] = True

        def bare_tag(release: FakeRelease) -> None:
            release.release["tag_name"] = "0.2.0"

        def no_appcast_asset(release: FakeRelease) -> None:
            release.release["assets"] = [a for a in release.release["assets"] if a["name"] != "appcast.xml"]

        def no_assets(release: FakeRelease) -> None:
            del release.release["assets"]

        cases = {
            "SHA256SUMS disagrees": (mutate(wrong_sums), "SHA256SUMS says"),
            "SHA256SUMS lacks the ZIP": (mutate(no_sums_entry), "has no entry"),
            "GitHub digest disagrees": (mutate(wrong_digest), "differs from the digest GitHub reports"),
            "appcast length disagrees": (mutate(wrong_length), "bytes, but it is"),
            "appcast version disagrees": (mutate(wrong_item_version), "item version is"),
            "appcast has no signature": (mutate(unsigned), "no sparkle:edSignature"),
            "appcast has a DTD": (mutate(with_dtd), "DOCTYPE or ENTITY"),
            "ZIP swapped, metadata fixed up": (mutate(swapped_zip), "did not verify against the pinned key"),
            "draft release": (mutate(draft), "draft or prerelease"),
            "prerelease": (mutate(prerelease), "draft or prerelease"),
            "tag without v": (mutate(bare_tag), "is not of the form"),
            "appcast asset missing": (mutate(no_appcast_asset), "missing assets: appcast.xml"),
            "asset list missing": (mutate(no_assets), "no assets list"),
            "signed by another key": (
                lambda: self.release("0.2.0", signer=self.other, embedded_key=self.pinned.public_b64),
                "did not verify against the pinned key",
            ),
            "app embeds another key": (
                lambda: self.release("0.2.0", embedded_key=self.other.public_b64),
                "SUPublicEDKey",
            ),
            "app reports another version": (
                lambda: self.release("0.2.0", CFBundleShortVersionString="0.1.0"),
                "CFBundleShortVersionString",
            ),
            "app has another identifier": (
                lambda: self.release("0.2.0", CFBundleIdentifier="com.example.other"),
                "CFBundleIdentifier",
            ),
        }
        for label, (build, message) in cases.items():
            with self.subTest(label):
                with self.assertRaisesRegex(BumpError, re.escape(message)):
                    self.bump(build())
                self.assertEqual(self.cask.read_text(encoding="utf-8"), self.original)
                self.assertEqual(self.outputs(), {})

    def test_main_turns_a_failure_into_exit_status_one_and_an_annotation(self) -> None:
        os.environ["GITHUB_ACTIONS"] = "true"
        release = self.release("0.2.0")
        release.release["draft"] = True
        stderr = io.StringIO()
        with self.serving(release) as stdout, contextlib.redirect_stderr(stderr):
            status = bump_cask.main(self.argv())
        self.assertEqual(status, 1)
        self.assertIn("::error title=Cask bump failed::", stdout.getvalue())
        self.assertIn("error: the latest release is a draft or prerelease", stderr.getvalue())
        self.assertEqual(self.cask.read_text(encoding="utf-8"), self.original)

    def test_main_reports_success_with_status_zero(self) -> None:
        release = self.release("0.2.0")
        with self.serving(release):
            self.assertEqual(bump_cask.main(self.argv()), 0)
        self.assertEqual(bump_cask.cask_version(self.cask.read_text(encoding="utf-8")), "0.2.0")


if __name__ == "__main__":
    unittest.main()
