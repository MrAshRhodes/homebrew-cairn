#!/usr/bin/env bash
# Checks the Cairn cask the way a user would: it installs the real app on a
# disposable GitHub Actions runner, inspects it, runs the commands the README
# documents, and removes it again with --zap. It refuses to run anywhere else
# because it deletes files. The app is never launched.
#
#   ci-validate.sh tap        the tap checked out for this run: brew style and
#                             brew audit first, then install, inspect, upgrade, zap
#   ci-validate.sh published  the same commands against the public tap on GitHub
#
# EXPECTED_VERSION (optional) is the version the installed app must report.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != "true" ]]
then
  echo "error: ci-validate.sh installs and removes software, so it only runs on GitHub Actions runners" >&2
  exit 2
fi

mode="${1:-}"
if [[ "${mode}" != "tap" && "${mode}" != "published" ]]
then
  echo "usage: ci-validate.sh tap|published" >&2
  exit 2
fi

bundle_id="io.github.mrashrhodes.cairn"
app="/Applications/Cairn.app"
summary_file="${GITHUB_STEP_SUMMARY:-/dev/null}"

say() { printf '\n==> %s\n' "$*"; }

fail() {
  echo "::error title=Cask validation failed::$*"
  exit 1
}

expect_equal() { # what, actual, expected
  if [[ "$2" != "$3" ]]
  then
    fail "$1: expected '$3' but found '$2'"
  fi
  echo "ok: $1 ($2)"
}

caskroom="$(brew --prefix)/Caskroom/cairn"
if [[ -e "${app}" || -e "${caskroom}" ]]
then
  fail "Cairn is already installed here; refusing to continue on a machine that is not disposable"
fi

brew --version
runner_macos="$(sw_vers -productVersion)"
runner_arch="$(uname -m)"
echo "Runner: macOS ${runner_macos} on ${runner_arch}"

if [[ "${mode}" == "tap" ]]
then
  # No --signing: Cairn is ad-hoc signed, which that check rejects. No --new or
  # --token-conflicts: they apply to submissions to the official tap.
  say "brew style"
  brew style mrashrhodes/cairn
  say "brew audit"
  brew audit --cask --strict --online mrashrhodes/cairn/cairn
fi

say "Install"
brew install --cask mrashrhodes/cairn/cairn

say "Inspect"
info_json="$(brew info --cask --json=v2 mrashrhodes/cairn/cairn)"
fields="$(python3 -c '
import json
import os
import sys

cask = json.load(sys.stdin)["casks"][0]
print("version\t" + str(cask["version"]))
print("installed\t" + str(cask.get("installed") or ""))
floor = ((cask.get("depends_on") or {}).get("macos") or {}).get(">=") or [""]
print("floor\t" + str(floor[0]))
for artifact in cask["artifacts"]:
    for stanza in artifact.get("zap") or []:
        for key in ("trash", "delete"):
            paths = stanza.get(key) or []
            for path in [paths] if isinstance(paths, str) else paths:
                print("zap\t" + os.path.expanduser(path))
' <<<"${info_json}")"

cask_version=""
installed_version=""
macos_floor=""
zap_paths=()
while IFS=$'\t' read -r key value
do
  case "${key}" in
    version) cask_version="${value}" ;;
    installed) installed_version="${value}" ;;
    floor) macos_floor="${value}" ;;
    zap) zap_paths+=("${value}") ;;
    *) fail "brew info produced an unexpected field: ${key}" ;;
  esac
done <<<"${fields}"

[[ -n "${cask_version}" ]] || fail "brew info did not report a cask version"
[[ "${macos_floor}" =~ ^[0-9]+$ ]] || fail "brew info reported no usable macOS floor (got '${macos_floor}')"
[[ ${#zap_paths[@]} -gt 0 ]] || fail "the cask declares no zap paths"
expect_equal "Homebrew installed the cask's version" "${installed_version}" "${cask_version}"
if [[ -n "${EXPECTED_VERSION:-}" ]]
then
  expect_equal "cask version is the verified release" "${cask_version}" "${EXPECTED_VERSION}"
fi

[[ -d "${app}" ]] || fail "${app} was not installed"
plist="${app}/Contents/Info.plist"
plist_value() { plutil -extract "$1" raw -o - "${plist}"; }
app_version="$(plist_value CFBundleShortVersionString)"
expect_equal "app version" "${app_version}" "${cask_version}"
app_bundle_id="$(plist_value CFBundleIdentifier)"
expect_equal "bundle identifier" "${app_bundle_id}" "${bundle_id}"

min_os="$(plist_value LSMinimumSystemVersion)"
min_os_major="${min_os%%.*}"
[[ "${min_os_major}" =~ ^[0-9]+$ ]] || fail "unexpected LSMinimumSystemVersion '${min_os}'"
if ((min_os_major > macos_floor))
then
  fail "the app needs macOS ${min_os} but the cask only requires macOS ${macos_floor}"
fi
echo "ok: app needs macOS ${min_os}, the cask requires macOS ${macos_floor}"

codesign --verify --deep --strict --verbose=2 "${app}"
echo "ok: code signature is intact"

executable="$(plist_value CFBundleExecutable)"
archs="$(lipo -archs "${app}/Contents/MacOS/${executable}")"
for arch in arm64 x86_64
do
  [[ " ${archs} " == *" ${arch} "* ]] || fail "the app binary has no ${arch} slice (found: ${archs})"
done
echo "ok: universal binary (${archs})"

say "Upgrade (already current, so nothing changes)"
brew upgrade --cask cairn
upgraded_version="$(plist_value CFBundleShortVersionString)"
expect_equal "app version after upgrade" "${upgraded_version}" "${cask_version}"

say "Plant a marker in every zap path"
for path in "${zap_paths[@]}"
do
  [[ "${path}" == "${HOME}/Library/"* ]] || fail "unexpected zap path outside ~/Library: ${path}"
  if [[ -e "${path}" || -L "${path}" ]]
  then
    fail "zap path already exists, refusing to plant a marker in it: ${path}"
  fi
  mkdir -p "$(dirname "${path}")"
  if [[ "${path}" == *.plist ]]
  then
    echo "marker" >"${path}"
  else
    mkdir -p "${path}"
    echo "marker" >"${path}/ci-marker.txt"
  fi
  echo "planted: ${path}"
done

say "Uninstall with --zap"
brew uninstall --cask --zap cairn

[[ ! -e "${app}" ]] || fail "${app} is still there after uninstalling"
[[ ! -e "${caskroom}" ]] || fail "${caskroom} is still there after uninstalling"
echo "ok: app and Caskroom entry are gone"
for path in "${zap_paths[@]}"
do
  if [[ -e "${path}" || -L "${path}" ]]
  then
    fail "zap left this behind: ${path}"
  fi
  echo "removed: ${path}"
done

{
  echo "### Cairn cask validation (${mode})"
  echo
  echo "- Runner: macOS ${runner_macos} on ${runner_arch}"
  echo "- Cask and app version: \`${cask_version}\` (\`${bundle_id}\`, needs macOS ${min_os})"
  echo "- Architectures in the app binary: \`${archs}\`"
  echo "- Install, upgrade and uninstall --zap all succeeded; the app and its Caskroom entry are gone"
  echo
  echo "| Zap path | Marker planted | After uninstall --zap |"
  echo "| --- | --- | --- |"
  for path in "${zap_paths[@]}"
  do
    echo "| \`${path}\` | yes | removed |"
  done
} >>"${summary_file}"
