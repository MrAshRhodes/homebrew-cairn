#!/usr/bin/env python3
"""Bump the Cairn cask to the latest GitHub release, but only after verifying it.

The cask is rewritten (version and sha256 only) when, and only when, all of
these hold for the newest non-draft, non-prerelease release:

  * its ZIP's SHA-256 equals the entry in the release's SHA256SUMS,
  * the Sparkle EdDSA (Ed25519) signature on the ZIP enclosure in the release's
    appcast.xml verifies against the public key pinned in this repository
    (never a key taken from the release itself), using OpenSSL 3,
  * the app inside the ZIP reports the release version and bundle identifier
    and embeds that same pinned key.

Any failure aborts with a non-zero exit status and leaves the cask untouched.
Standard library only; OpenSSL >= 3 (not LibreSSL) must be available.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import http.client
import json
import os
import plistlib
import posixpath
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar
from xml.parsers.expat import ExpatError

DEFAULT_REPO = "MrAshRhodes/cairn"
DEFAULT_CASK = "Casks/cairn.rb"
DEFAULT_PUBKEY = "keys/sparkle-public-ed-key.txt"
DEFAULT_WORKDIR = ".scratch/bump"

APP_BUNDLE = "Cairn.app"
BUNDLE_ID = "io.github.mrashrhodes.cairn"
SPARKLE_NS = "http://www.andymatuschak.org/xml-namespaces/sparkle"
# DER SubjectPublicKeyInfo header for a raw 32-byte Ed25519 public key.
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")

MAX_ZIP_BYTES = 256 * 1024 * 1024
MAX_TEXT_BYTES = 1024 * 1024
MAX_PLIST_BYTES = 1024 * 1024
MAX_JSON_BYTES = 8 * 1024 * 1024
REQUEST_TIMEOUT = 60
USER_AGENT = "homebrew-cairn-bump (+https://github.com/MrAshRhodes/homebrew-cairn)"

_VERSION_RE = re.compile(r"v?([0-9]{1,9}(?:\.[0-9]{1,9})+)")
_TAG_RE = re.compile(r"v([0-9]{1,9}(?:\.[0-9]{1,9})+)")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SUMS_LINE_RE = re.compile(r"([0-9a-fA-F]{64}) [ *](.+)")
_OPENSSL_VERSION_RE = re.compile(r"OpenSSL ([0-9]+)\.([0-9]+)\.([0-9]+)")
_CASK_VERSION_RE = re.compile(r'^  version "([^"\n]*)"[ \t]*$', re.MULTILINE)
_CASK_SHA256_RE = re.compile(r'^  sha256 "([^"\n]*)"[ \t]*$', re.MULTILINE)
_CASK_URL_RE = re.compile(r'^  url "([^"\n]*)"', re.MULTILINE)
_DTD_RE = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)

_OPENSSL_FALLBACKS = (
    "/opt/homebrew/opt/openssl@3/bin/openssl",
    "/usr/local/opt/openssl@3/bin/openssl",
    "/opt/homebrew/bin/openssl",
    "/usr/local/bin/openssl",
)

T = TypeVar("T")


class BumpError(Exception):
    """A check failed or the input is not what we expect; nothing may change."""


# ---------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------


def parse_version(text: str) -> Tuple[int, ...]:
    """Parse "1.2.3" or "v1.2.3" into (1, 2, 3); anything else is an error."""
    match = _VERSION_RE.fullmatch(text)
    if not match:
        raise BumpError(f"unsupported version format: {text!r}")
    return tuple(int(part) for part in match.group(1).split("."))


def compare_versions(left: str, right: str) -> int:
    """Return -1, 0 or 1; missing trailing components count as zero."""
    a, b = parse_version(left), parse_version(right)
    width = max(len(a), len(b))
    a += (0,) * (width - len(a))
    b += (0,) * (width - len(b))
    return (a > b) - (a < b)


def version_from_tag(tag: str) -> str:
    """The release tag must be exactly "v<version>", as the cask URL assumes."""
    match = _TAG_RE.fullmatch(tag)
    if not match:
        raise BumpError(f"release tag {tag!r} is not of the form v<major>.<minor>[.<patch>...]")
    return match.group(1)


# ---------------------------------------------------------------------------
# Release metadata parsing
# ---------------------------------------------------------------------------


def parse_sha256sums(text: str) -> Dict[str, str]:
    """Parse `sha256sum`-style text into {file name: lowercase hex digest}.

    A leading "./" on a name is dropped. Malformed lines and duplicate names
    are errors rather than being skipped, so the lookup cannot be ambiguous.
    """
    sums: Dict[str, str] = {}
    for number, raw in enumerate(text.split("\n"), start=1):
        line = raw.rstrip("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _SUMS_LINE_RE.fullmatch(line)
        if not match:
            raise BumpError(f"SHA256SUMS line {number} is not '<sha256>  <file name>'")
        name = match.group(2)
        if name.startswith("./"):
            name = name[2:]
        if not name:
            raise BumpError(f"SHA256SUMS line {number} has an empty file name")
        if name in sums:
            raise BumpError(f"SHA256SUMS lists {name!r} more than once")
        sums[name] = match.group(1).lower()
    return sums


@dataclass(frozen=True)
class Enclosure:
    url: str
    length: int
    ed_signature: str
    short_version: Optional[str]


def parse_appcast(xml: bytes, asset_name: str) -> Enclosure:
    """Return the appcast enclosure whose URL ends in `asset_name`.

    The match is by URL basename because Sparkle may publish the URL with a
    different owner/repo capitalisation than the one used for the download.
    """
    try:
        text = xml.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BumpError("appcast.xml is not valid UTF-8") from exc
    if _DTD_RE.search(text):
        raise BumpError("appcast.xml must not contain DOCTYPE or ENTITY declarations")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise BumpError(f"appcast.xml is not well-formed XML: {exc}") from exc

    matches = []
    for item in root.iter("item"):
        for enclosure in item.findall("enclosure"):
            path = urllib.parse.unquote(urllib.parse.urlsplit(enclosure.get("url") or "").path)
            if posixpath.basename(path) == asset_name:
                matches.append((item, enclosure))
    if len(matches) != 1:
        raise BumpError(f"appcast.xml must contain exactly one enclosure for {asset_name}, found {len(matches)}")

    item, enclosure = matches[0]
    signature = enclosure.get(f"{{{SPARKLE_NS}}}edSignature")
    if not signature:
        raise BumpError(f"appcast.xml enclosure for {asset_name} has no sparkle:edSignature")
    try:
        length = int(enclosure.get("length", ""))
    except ValueError as exc:
        raise BumpError(f"appcast.xml enclosure for {asset_name} has no valid length") from exc
    short = item.findtext(f"{{{SPARKLE_NS}}}shortVersionString")
    return Enclosure(
        url=enclosure.get("url", ""),
        length=length,
        ed_signature=signature.strip(),
        short_version=short.strip() if short else None,
    )


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


def decode_base64(value: str, expected_length: int, what: str) -> bytes:
    try:
        raw = base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BumpError(f"{what} is not valid base64") from exc
    if len(raw) != expected_length:
        raise BumpError(f"{what} must be {expected_length} bytes, got {len(raw)}")
    return raw


def read_pinned_key(path: Path) -> str:
    """Return the pinned Sparkle public key as canonical base64 text."""
    try:
        text = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise BumpError(f"cannot read pinned public key {path}: {exc}") from exc
    decode_base64(text, 32, f"pinned public key in {path}")
    return text


def public_key_pem(public_key_b64: str) -> str:
    raw = decode_base64(public_key_b64, 32, "Ed25519 public key")
    body = base64.b64encode(ED25519_SPKI_PREFIX + raw).decode("ascii")
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"


def openssl_version(openssl: str) -> Tuple[int, int, int]:
    """Return the OpenSSL version; reject LibreSSL and anything older than 3.0."""
    try:
        proc = subprocess.run([openssl, "version"], capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise BumpError(f"cannot run {openssl!r}: {exc}") from exc
    banner = proc.stdout.strip()
    match = _OPENSSL_VERSION_RE.match(banner)
    if proc.returncode != 0 or not match:
        raise BumpError(
            f"{openssl!r} is not OpenSSL 3 ({banner or proc.stderr.strip()!r}); "
            "LibreSSL cannot verify raw Ed25519 signatures"
        )
    version = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    if version[0] < 3:
        raise BumpError(f"OpenSSL >= 3.0 is required to verify Ed25519 signatures, found {banner!r}")
    return version


def find_openssl(explicit: Optional[str] = None) -> str:
    """Pick an OpenSSL >= 3 binary; an explicit choice must itself be usable."""
    if explicit:
        openssl_version(explicit)
        return explicit
    tried: List[str] = []
    for candidate in (os.environ.get("OPENSSL"), shutil.which("openssl"), *_OPENSSL_FALLBACKS):
        if not candidate or candidate in tried:
            continue
        tried.append(candidate)
        try:
            openssl_version(candidate)
        except BumpError:
            continue
        return candidate
    raise BumpError(f"no OpenSSL >= 3.0 found (tried: {', '.join(tried) or 'none'}); install it or pass --openssl")


def verify_ed25519(openssl: str, public_key_b64: str, signature_b64: str, data_file: Path, workdir: Path) -> None:
    """Verify a raw Ed25519 signature over the bytes of `data_file`.

    Raises BumpError unless OpenSSL reports a successful verification.
    """
    pem = public_key_pem(public_key_b64)
    signature = decode_base64(signature_b64, 64, "Ed25519 signature")
    openssl_version(openssl)

    workdir.mkdir(parents=True, exist_ok=True)
    pem_path = workdir / "sparkle-public-key.pem"
    signature_path = workdir / "signature.bin"
    pem_path.write_text(pem, encoding="ascii")
    signature_path.write_bytes(signature)

    command = [
        openssl, "pkeyutl", "-verify", "-rawin", "-pubin",
        "-inkey", str(pem_path), "-sigfile", str(signature_path), "-in", str(data_file),
    ]  # fmt: skip
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=300, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise BumpError(f"could not run OpenSSL to verify the signature: {exc}") from exc
    if proc.returncode != 0 or "Signature Verified Successfully" not in proc.stdout:
        detail = (proc.stdout + proc.stderr).strip().replace("\n", " ")
        raise BumpError(f"Ed25519 signature on {data_file.name} did not verify against the pinned key ({detail})")


# ---------------------------------------------------------------------------
# Downloaded artifacts
# ---------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_app_bundle(zip_path: Path, version: str, public_key_b64: str) -> None:
    """Check the signed ZIP really contains this version of Cairn.

    The Ed25519 signature authenticates the bytes but not which release they
    belong to, so this guards against an old, validly signed ZIP being
    republished under a newer tag.
    """
    member = f"{APP_BUNDLE}/Contents/Info.plist"
    try:
        with zipfile.ZipFile(zip_path) as archive:
            try:
                info = archive.getinfo(member)
            except KeyError as exc:
                raise BumpError(f"{zip_path.name} contains no {member}") from exc
            if info.file_size > MAX_PLIST_BYTES:
                raise BumpError(f"{member} in {zip_path.name} is unexpectedly large")
            plist = plistlib.loads(archive.read(info))
    except zipfile.BadZipFile as exc:
        raise BumpError(f"{zip_path.name} is not a valid ZIP archive: {exc}") from exc
    except (ValueError, ExpatError) as exc:
        raise BumpError(f"{member} in {zip_path.name} is not a valid property list: {exc}") from exc

    expected = {
        "CFBundleShortVersionString": version,
        "CFBundleIdentifier": BUNDLE_ID,
        "SUPublicEDKey": public_key_b64,
    }
    for key, wanted in expected.items():
        found = plist.get(key) if isinstance(plist, dict) else None
        if found != wanted:
            raise BumpError(f"{member} has {key} = {found!r}, expected {wanted!r}")


# ---------------------------------------------------------------------------
# Cask editing
# ---------------------------------------------------------------------------


def _single(pattern: "re.Pattern[str]", text: str, what: str) -> str:
    found = pattern.findall(text)
    if len(found) != 1:
        raise BumpError(f"expected exactly one top-level {what} line in the cask, found {len(found)}")
    return found[0]


def cask_version(text: str) -> str:
    return _single(_CASK_VERSION_RE, text, "version")


def cask_sha256(text: str) -> str:
    return _single(_CASK_SHA256_RE, text, "sha256")


def cask_url(text: str, version: str) -> str:
    """The cask's download URL with `#{version}` expanded."""
    return _single(_CASK_URL_RE, text, "url").replace("#{version}", version)


def rewrite_cask(text: str, new_version: str, new_sha256: str) -> str:
    """Return the cask text with only the version and sha256 lines replaced."""
    parse_version(new_version)
    if new_version.startswith("v"):
        raise BumpError(f"cask version must not start with 'v': {new_version!r}")
    if not _SHA256_RE.fullmatch(new_sha256):
        raise BumpError(f"not a lowercase hex SHA-256: {new_sha256!r}")
    cask_version(text)
    cask_sha256(text)
    if "#{version}" not in _single(_CASK_URL_RE, text, "url"):
        raise BumpError("the cask url no longer derives from #{version}; update it by hand")

    updated = _CASK_VERSION_RE.sub(lambda _m: f'  version "{new_version}"', text, count=1)
    updated = _CASK_SHA256_RE.sub(lambda _m: f'  sha256 "{new_sha256}"', updated, count=1)
    if (
        cask_version(updated) != new_version
        or cask_sha256(updated) != new_sha256
        or updated.count("\n") != text.count("\n")
    ):
        raise BumpError("internal error: cask rewrite did not produce the expected result")
    return updated


def write_text_atomic(path: Path, text: str) -> None:
    partial = path.with_name(path.name + ".part")
    partial.write_text(text, encoding="utf-8")
    os.replace(partial, path)


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------


def _retrying(url: str, action: Callable[[], T], attempts: int = 3) -> T:
    last: Optional[BaseException] = None
    for attempt in range(1, attempts + 1):
        try:
            return action()
        except urllib.error.HTTPError as exc:
            if exc.code < 500 and exc.code != 429:
                raise BumpError(f"HTTP {exc.code} for {url}") from exc
            last = exc
        except (OSError, http.client.HTTPException) as exc:
            last = exc
        if attempt < attempts:
            time.sleep(2**attempt)
    raise BumpError(f"giving up on {url} after {attempts} attempts: {last}") from last


def _open(url: str, token: Optional[str], accept: Optional[str]) -> Any:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https":
        raise BumpError(f"refusing non-HTTPS URL: {url}")
    headers = {"User-Agent": USER_AGENT}
    if accept:
        headers["Accept"] = accept
    # The token only ever goes to the API host, never to download redirects.
    if token and parts.hostname == "api.github.com":
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=REQUEST_TIMEOUT)


def fetch_json(url: str, token: Optional[str]) -> Any:
    def action() -> bytes:
        with _open(url, token, "application/vnd.github+json") as response:
            data = response.read(MAX_JSON_BYTES + 1)
        if len(data) > MAX_JSON_BYTES:
            raise BumpError(f"response from {url} is too large")
        return data

    try:
        return json.loads(_retrying(url, action))
    except ValueError as exc:
        raise BumpError(f"{url} did not return valid JSON: {exc}") from exc


def download(url: str, destination: Path, max_bytes: int) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(destination.name + ".part")

    def action() -> None:
        total = 0
        with _open(url, None, None) as response, partial.open("wb") as out:
            for chunk in iter(lambda: response.read(1024 * 1024), b""):
                total += len(chunk)
                if total > max_bytes:
                    raise BumpError(f"{url} is larger than {max_bytes} bytes")
                out.write(chunk)

    try:
        _retrying(url, action)
        os.replace(partial, destination)
    finally:
        partial.unlink(missing_ok=True)
    return destination


# ---------------------------------------------------------------------------
# Release verification
# ---------------------------------------------------------------------------


def zip_name(version: str) -> str:
    return f"Cairn-{version}-universal.zip"


def release_url(repo: str, version: str, asset: str) -> str:
    return f"https://github.com/{repo}/releases/download/v{version}/{asset}"


def latest_release_version(release: Any) -> str:
    """Validate the API's "latest release" object and return its version."""
    if not isinstance(release, dict):
        raise BumpError("unexpected response from the GitHub releases API")
    if release.get("draft") is not False or release.get("prerelease") is not False:
        raise BumpError("the latest release is a draft or prerelease; refusing to use it")
    tag = release.get("tag_name")
    if not isinstance(tag, str):
        raise BumpError("the latest release has no tag_name")
    return version_from_tag(tag)


@dataclass(frozen=True)
class VerifiedRelease:
    version: str
    sha256: str
    zip_url: str
    zip_path: Path


def verify_release(
    repo: str,
    version: str,
    release: Dict[str, Any],
    public_key_b64: str,
    openssl: str,
    workdir: Path,
) -> VerifiedRelease:
    archive = zip_name(version)
    listed_assets = release.get("assets")
    if not isinstance(listed_assets, list):
        raise BumpError("the release object has no assets list")
    assets = {a.get("name"): a for a in listed_assets if isinstance(a, dict)}
    missing = [name for name in (archive, "SHA256SUMS", "appcast.xml") if name not in assets]
    if missing:
        raise BumpError(f"release v{version} is missing assets: {', '.join(missing)}")

    release_dir = workdir / f"v{version}"
    zip_path = download(release_url(repo, version, archive), release_dir / archive, MAX_ZIP_BYTES)
    sums_path = download(release_url(repo, version, "SHA256SUMS"), release_dir / "SHA256SUMS", MAX_TEXT_BYTES)
    appcast_path = download(release_url(repo, version, "appcast.xml"), release_dir / "appcast.xml", MAX_TEXT_BYTES)

    actual = sha256_file(zip_path)

    try:
        sums = parse_sha256sums(sums_path.read_text(encoding="utf-8"))
    except UnicodeDecodeError as exc:
        raise BumpError("SHA256SUMS is not valid UTF-8") from exc
    listed = sums.get(archive)
    if listed is None:
        raise BumpError(f"SHA256SUMS has no entry for {archive}")
    if listed != actual:
        raise BumpError(f"{archive} SHA-256 is {actual}, but SHA256SUMS says {listed}")
    print(f"ok: {archive} SHA-256 matches SHA256SUMS ({actual})")

    digest = assets[archive].get("digest")
    if isinstance(digest, str) and digest.startswith("sha256:") and digest[len("sha256:") :] != actual:
        raise BumpError(f"{archive} SHA-256 {actual} differs from the digest GitHub reports ({digest})")

    enclosure = parse_appcast(appcast_path.read_bytes(), archive)
    if enclosure.length != zip_path.stat().st_size:
        raise BumpError(f"appcast.xml says {archive} is {enclosure.length} bytes, but it is {zip_path.stat().st_size}")
    if enclosure.short_version != version:
        raise BumpError(f"appcast.xml item version is {enclosure.short_version!r}, expected {version!r}")
    verify_ed25519(openssl, public_key_b64, enclosure.ed_signature, zip_path, workdir / "verify")
    print(f"ok: Sparkle Ed25519 signature on {archive} verifies against the pinned public key")

    check_app_bundle(zip_path, version, public_key_b64)
    print(f"ok: {APP_BUNDLE} in {archive} is {BUNDLE_ID} {version} and embeds the pinned key")

    return VerifiedRelease(version, actual, release_url(repo, version, archive), zip_path)


# ---------------------------------------------------------------------------
# GitHub Actions plumbing
# ---------------------------------------------------------------------------


def write_outputs(**values: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            if "\n" in value or "\r" in value:
                raise BumpError(f"refusing to write a multi-line value for output {key}")
            handle.write(f"{key}={value}\n")


def write_summary(markdown: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(markdown.rstrip() + "\n")


def _annotation(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--repo", default=DEFAULT_REPO, help="GitHub repository publishing the releases")
    parser.add_argument("--cask", default=DEFAULT_CASK, help="path of the cask file to update")
    parser.add_argument("--pubkey", default=DEFAULT_PUBKEY, help="file holding the pinned Sparkle public key (base64)")
    parser.add_argument("--workdir", default=DEFAULT_WORKDIR, help="directory for downloads and verification files")
    parser.add_argument("--openssl", default=None, help="OpenSSL >= 3 binary (default: search PATH and Homebrew)")
    parser.add_argument("--dry-run", action="store_true", help="verify a newer release but do not modify the cask")
    parser.add_argument(
        "--verify-current",
        action="store_true",
        help="also verify the release the cask already pins when it is up to date; never modifies the cask",
    )
    return parser.parse_args(argv)


def run(args: argparse.Namespace) -> int:
    cask_path = Path(args.cask)
    try:
        text = cask_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BumpError(f"cannot read {cask_path}: {exc}") from exc
    current = cask_version(text)
    parse_version(current)
    print(f"Cask version: {current}")

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    release = fetch_json(f"https://api.github.com/repos/{args.repo}/releases/latest", token)
    latest = latest_release_version(release)
    print(f"Latest release of {args.repo}: v{latest}")

    relation = compare_versions(latest, current)
    if relation < 0:
        message = f"Latest release v{latest} is older than cask version {current}; not downgrading."
        print(f"::warning::{message}" if os.environ.get("GITHUB_ACTIONS") else message)
        write_outputs(changed="false", version=current)
        write_summary(f"### Cask bump\n\n{message}")
        return 0
    if relation == 0 and not args.verify_current:
        print(f"Cask is up to date ({current}); nothing to do.")
        write_outputs(changed="false", version=current)
        write_summary(f"### Cask bump\n\nCask is up to date at **{current}**; nothing to do.")
        return 0

    expected_url = release_url(args.repo, latest, zip_name(latest))
    if cask_url(text, latest).lower() != expected_url.lower():
        raise BumpError(f"the cask url resolves to {cask_url(text, latest)}, not the verified {expected_url}")

    public_key = read_pinned_key(Path(args.pubkey))
    openssl = find_openssl(args.openssl)
    major, minor, patch = openssl_version(openssl)
    print(f"Using {openssl} (OpenSSL {major}.{minor}.{patch})")
    verified = verify_release(args.repo, latest, release, public_key, openssl, Path(args.workdir))

    if relation == 0:
        if cask_sha256(text) != verified.sha256:
            raise BumpError(f"the cask pins sha256 {cask_sha256(text)}, but the verified release asset is {verified.sha256}")
        print(f"The pinned release v{current} verified; the cask is correct.")
        write_outputs(changed="false", version=current)
        write_summary(f"### Cask bump\n\nRe-verified the pinned release **v{current}**; the cask is correct.")
        return 0

    updated = rewrite_cask(text, latest, verified.sha256)
    if args.dry_run:
        print(f"Dry run: would bump {current} -> {latest} (sha256 {verified.sha256}); {cask_path} not modified.")
        write_outputs(changed="false", version=current)
        return 0
    write_text_atomic(cask_path, updated)
    print(f"Updated {cask_path}: {current} -> {latest} (sha256 {verified.sha256})")
    write_outputs(changed="true", version=latest, sha256=verified.sha256)
    write_summary(
        f"### Cask bump\n\nVerified **v{latest}** and updated the cask from {current}.\n\n"
        f"- ZIP SHA-256: `{verified.sha256}`\n"
        "- SHA256SUMS match, Sparkle Ed25519 signature verified against the pinned key"
    )
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    try:
        return run(args)
    except BumpError as exc:
        if os.environ.get("GITHUB_ACTIONS"):
            print(f"::error title=Cask bump failed::{_annotation(str(exc))}")
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
