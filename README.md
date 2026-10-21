# homebrew-cairn

A Homebrew tap for [Cairn](https://github.com/MrAshRhodes/cairn), an experimental local-first browser for macOS with Spaces, vertical tabs and Boosts. See the [product site](https://mrashrhodes.github.io/cairn/) for what it is.

The cask installs **Cairn 0.1.0, the universal WebKit build** (Apple silicon and Intel). It needs macOS 14 Sonoma or later.

## Install, upgrade, uninstall

```sh
brew install --cask mrashrhodes/cairn/cairn
brew upgrade --cask cairn
brew uninstall --cask --zap cairn
```

- The first command adds this tap automatically and installs `Cairn.app` into `/Applications`.
- The second upgrades Cairn once this tap carries a newer verified release; today it has nothing to do.
- The third removes the app **and** Cairn's data (see [What `--zap` deletes](#what---zap-deletes)). Use `brew uninstall --cask cairn` to keep the data.

## First launch: Gatekeeper

Cairn is ad-hoc signed and is not notarized by Apple, so macOS blocks it the first time you open it. Open Cairn once, then go to **System Settings > Privacy & Security**, scroll to the Security section and click **Open Anyway** for Cairn. This tap does not try to get around that check.

## Why a tap

The official `homebrew/cask` repository only takes apps that pass Gatekeeper without that extra step. Cairn is not notarized, so it lives here instead.

## How the cask stays current

`.github/workflows/bump.yml` runs every six hours. For the newest published (not draft, not pre-release) GitHub release of `MrAshRhodes/cairn` it updates the cask only if all of these hold:

1. the ZIP's SHA-256 equals its entry in the release's `SHA256SUMS`;
2. the Sparkle Ed25519 signature on the ZIP in the release's `appcast.xml` verifies against the public key pinned in [`keys/sparkle-public-ed-key.txt`](keys/sparkle-public-ed-key.txt), never a key taken from the release itself;
3. the app inside the ZIP has the expected bundle identifier and version and embeds that same key.

Then the candidate cask is installed, inspected, upgraded and zapped on both macOS runner architectures, and only after that is a commit named `cairn <version>` pushed to `main`. Scheduled runs also re-verify the release the cask pins today, so a swapped release file is noticed.

Two consequences worth knowing:

- Publishing a newer release that passes these checks is enough to update this tap, with no review step in between.
- A commit pushed with the workflow's `GITHUB_TOKEN` does not start other workflows, so a bump is validated by the bump workflow itself. GitHub also pauses scheduled workflows after 60 days without repository activity; re-enable them in the Actions tab if that happens.

## Verify a download yourself

You need OpenSSL 3 or newer (macOS's built-in LibreSSL will not do; `brew install openssl@3` provides one). Pinned Sparkle public key:

```
ugn8YkRCxDuzUN63cb+sFMayO6As26BL/1FBbbUs9a8=
```

```sh
V=0.1.0
BASE=https://github.com/MrAshRhodes/cairn/releases/download/v$V
curl -fsSLO $BASE/Cairn-$V-universal.zip -O $BASE/SHA256SUMS -O $BASE/appcast.xml

# 1. The checksum in SHA256SUMS
grep "Cairn-$V-universal.zip" SHA256SUMS | shasum -a 256 -c -

# 2. The Sparkle signature, checked against the pinned key
{ printf '302a300506032b6570032100' | xxd -r -p; echo 'ugn8YkRCxDuzUN63cb+sFMayO6As26BL/1FBbbUs9a8=' | base64 -d; } > sparkle-key.der
grep -o 'sparkle:edSignature="[^"]*"' appcast.xml | cut -d'"' -f2 | base64 -d > cairn.sig
openssl pkeyutl -verify -rawin -pubin -keyform DER -inkey sparkle-key.der -sigfile cairn.sig -in Cairn-$V-universal.zip
```

The last command prints `Signature Verified Successfully`.

## What `--zap` deletes

`brew uninstall --cask --zap cairn` moves these to the Trash, so it deletes your Cairn profile (Spaces, history, settings):

- `~/Library/Application Support/Cairn`
- `~/Library/Caches/io.github.mrashrhodes.cairn`
- `~/Library/HTTPStorages/io.github.mrashrhodes.cairn`
- `~/Library/Preferences/io.github.mrashrhodes.cairn.plist`
- `~/Library/Saved Application State/io.github.mrashrhodes.cairn.savedState`
- `~/Library/WebKit/io.github.mrashrhodes.cairn`

## Development

```sh
python3 -m unittest -v
```

The tests need OpenSSL 3 or newer; without it the signature tests are skipped unless `TAP_TESTS_REQUIRE_OPENSSL=1` is set, which turns the skip into a failure (CI sets it). CI (`.github/workflows/ci.yml`) runs the tests, ShellCheck and actionlint, then installs, inspects, upgrades and zaps the cask on `macos-15` and `macos-15-intel`, and once more against the published tap on a fresh runner. The audit is `brew audit --cask --strict --online`; it leaves out `--signing` (it rejects an ad-hoc signed app) and `--new` / `--token-conflicts` (they are for submissions to `homebrew/cask`).

## License

[Apache-2.0](LICENSE).
