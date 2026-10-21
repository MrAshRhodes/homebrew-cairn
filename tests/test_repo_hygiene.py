"""Repository-wide rules: the cask's shape, workflow safety, and wording this tap promises to keep."""

from __future__ import annotations

import os
import re
import subprocess
import unittest
from collections import Counter
from pathlib import Path
from typing import Dict, List

from tests.support import REPO_ROOT, bump_cask

CASK = (REPO_ROOT / "Casks" / "cairn.rb").read_text(encoding="utf-8")
README = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
VALIDATE_SCRIPT = (REPO_ROOT / "scripts" / "ci-validate.sh").read_text(encoding="utf-8")
WORKFLOWS = {path.name: path.read_text(encoding="utf-8") for path in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml"))}
PINNED_KEY = "ugn8YkRCxDuzUN63cb+sFMayO6As26BL/1FBbbUs9a8="

# The commands users are told to run, which CI must run verbatim against the published tap.
USER_COMMANDS = (
    "brew install --cask mrashrhodes/cairn/cairn",
    "brew upgrade --cask cairn",
    "brew uninstall --cask --zap cairn",
)


def shipped_files() -> List[Path]:
    paths = [
        REPO_ROOT / "README.md",
        *REPO_ROOT.glob("Casks/*.rb"),
        *REPO_ROOT.glob("scripts/*"),
        *REPO_ROOT.glob(".github/**/*.yml"),
    ]
    return [path for path in paths if path.is_file()]


def top_level_block(text: str, key: str) -> List[str]:
    """The lines indented under a top-level `key:` line."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if re.fullmatch(rf"{re.escape(key)}:\s*(#.*)?", line):
            block: List[str] = []
            for follower in lines[index + 1 :]:
                if follower.strip() and not follower.startswith(" "):
                    break
                block.append(follower)
            return block
    return []


def jobs_of(text: str) -> Dict[str, str]:
    result: Dict[str, List[str]] = {}
    current = None
    for line in top_level_block(text, "jobs"):
        header = re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*", line)
        if header:
            current = header.group(1)
            result[current] = []
        elif current is not None:
            result[current].append(line)
    return {name: "\n".join(lines) for name, lines in result.items()}


def permissions_in(lines: List[str], indent: int) -> Dict[str, str]:
    """Parse the `permissions:` mapping whose key sits at `indent` spaces, if there is one."""
    for index, line in enumerate(lines):
        if re.fullmatch(rf" {{{indent}}}permissions:\s*", line):
            pairs: Dict[str, str] = {}
            for follower in lines[index + 1 :]:
                match = re.fullmatch(rf" {{{indent + 2}}}([a-z-]+):\s*([a-z-]+)\s*", follower)
                if not match:
                    break
                pairs[match.group(1)] = match.group(2)
            return pairs
    return {}


def run_scripts(text: str) -> List[str]:
    """The shell text of every `run:` step."""
    lines = text.splitlines()
    scripts: List[str] = []
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*(?:- )?)run:\s*(.*)$", line)
        if not match:
            continue
        key_column = len(match.group(1))
        if match.group(2) and match.group(2)[0] not in "|>":
            scripts.append(match.group(2))
            continue
        body: List[str] = []
        for follower in lines[index + 1 :]:
            if follower.strip() and len(follower) - len(follower.lstrip()) <= key_column:
                break
            body.append(follower)
        scripts.append("\n".join(body))
    return scripts


class CaskTests(unittest.TestCase):
    STANZAS = {"version", "sha256", "url", "name", "desc", "homepage", "livecheck", "depends_on", "app", "zap", "caveats"}

    def test_it_has_exactly_the_stanzas_a_plain_app_cask_needs(self) -> None:
        self.assertTrue(CASK.startswith('cask "cairn" do\n'))
        self.assertTrue(CASK.endswith("\nend\n"))
        stanzas = re.findall(r"^  ([a-z][a-z_0-9]*)\b", CASK, re.MULTILINE)
        counts = Counter(name for name in stanzas if name != "end")  # `end` closes the livecheck block
        self.assertEqual(set(counts), self.STANZAS)
        self.assertEqual({name: count for name, count in counts.items() if count != 1}, {})

    def test_it_has_no_install_scripts_or_privileged_commands(self) -> None:
        for word in ("preflight", "postflight", "installer", "pkg ", "system_command", "sudo", "binary ", "uninstall"):
            self.assertNotIn(word, CASK)

    def test_version_and_checksum_are_well_formed(self) -> None:
        self.assertRegex(bump_cask.cask_version(CASK), r"^[0-9]+(\.[0-9]+)+$")
        self.assertRegex(bump_cask.cask_sha256(CASK), r"^[0-9a-f]{64}$")

    def test_the_download_url_is_the_one_the_bump_script_verifies(self) -> None:
        version = bump_cask.cask_version(CASK)
        expected = bump_cask.release_url(bump_cask.DEFAULT_REPO, version, bump_cask.zip_name(version))
        self.assertEqual(bump_cask.cask_url(CASK, version), expected)
        self.assertIn("v#{version}/Cairn-#{version}-universal.zip", CASK)

    def test_identity_stanzas(self) -> None:
        self.assertIn('  name "Cairn"\n', CASK)
        self.assertIn('  homepage "https://github.com/MrAshRhodes/cairn"\n', CASK)
        self.assertIn(f'  app "{bump_cask.APP_BUNDLE}"\n', CASK)
        self.assertIn("  depends_on macos: :sonoma\n", CASK)

    def test_description_follows_homebrew_style(self) -> None:
        match = re.search(r'^  desc "([^"]*)"$', CASK, re.MULTILINE)
        self.assertIsNotNone(match)
        desc = match.group(1)
        self.assertEqual(desc, desc.strip())
        self.assertLessEqual(len(desc), 80)
        self.assertFalse(desc.endswith("."))
        self.assertNotRegex(desc, r"^(Cairn|A|An|The)\b")
        self.assertNotIn("macOS", desc)

    def test_zap_only_touches_files_that_belong_to_cairn(self) -> None:
        block = re.search(r"zap trash: \[\n(.*?)\n  \]", CASK, re.DOTALL)
        self.assertIsNotNone(block)
        paths = re.findall(r'^    "([^"]+)",$', block.group(1), re.MULTILINE)
        self.assertGreaterEqual(len(paths), 1)
        self.assertEqual(len(paths), len(set(paths)))
        leaf = re.compile(rf"^(Cairn|{re.escape(bump_cask.BUNDLE_ID)}(\.plist|\.savedState)?)$")
        for path in paths:
            with self.subTest(path=path):
                parts = path.split("/")
                self.assertEqual(parts[:2], ["~", "Library"])
                self.assertEqual(len(parts), 4, "exactly <Library folder>/<Cairn item>")
                self.assertRegex(parts[3], leaf)
                self.assertNotRegex(path, r"[*?\[\]{}]|\.\.")

    def test_caveats_are_honest_about_gatekeeper(self) -> None:
        self.assertIn("not notarized", CASK)
        self.assertIn('"Open Anyway"', CASK)


class WordingTests(unittest.TestCase):
    def test_there_is_something_to_check(self) -> None:
        names = {path.name for path in shipped_files()}
        self.assertTrue({"README.md", "cairn.rb", "bump_cask.py", "ci-validate.sh", "ci.yml", "bump.yml"} <= names)

    def test_nothing_advises_bypassing_gatekeeper(self) -> None:
        pattern = re.compile(r"\b(xattr|spctl)\b|--no-quarantine|HOMEBREW_CASK_OPTS", re.IGNORECASE)
        for path in shipped_files():
            with self.subTest(path=path.name):
                self.assertIsNone(pattern.search(path.read_text(encoding="utf-8")))

    def test_notarization_is_only_ever_mentioned_as_absent(self) -> None:
        negation = re.compile(r"\b(?:not|no|never|without|isn't)\s+$", re.IGNORECASE)
        for path in shipped_files():
            text = path.read_text(encoding="utf-8")
            for match in re.finditer(r"notariz\w*", text, re.IGNORECASE):
                with self.subTest(path=path.name, offset=match.start()):
                    self.assertRegex(text[max(0, match.start() - 12) : match.start()], negation)


class WorkflowTests(unittest.TestCase):
    def test_both_workflows_exist(self) -> None:
        self.assertEqual(sorted(WORKFLOWS), ["bump.yml", "ci.yml"])

    def test_every_action_is_pinned_to_a_commit_with_a_version_comment(self) -> None:
        pattern = re.compile(r"^\s*(?:- )?uses:\s*(\S+)(?:\s+#\s*(.*))?$")
        seen = 0
        for name, text in WORKFLOWS.items():
            for line in text.splitlines():
                match = pattern.match(line)
                if not match:
                    continue
                seen += 1
                with self.subTest(workflow=name, line=line.strip()):
                    self.assertRegex(match.group(1), r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
                    self.assertRegex(match.group(2) or "", r"^v?[0-9]")
        self.assertGreater(seen, 0)

    def test_the_default_token_is_read_only(self) -> None:
        for name, text in WORKFLOWS.items():
            with self.subTest(workflow=name):
                self.assertEqual(permissions_in(text.splitlines(), 0), {"contents": "read"})

    def test_write_access_belongs_to_the_one_job_that_pushes_the_bump(self) -> None:
        self.assertNotRegex(WORKFLOWS["ci.yml"], r":\s*write\b")
        writers = {}
        for job, block in jobs_of(WORKFLOWS["bump.yml"]).items():
            granted = permissions_in(block.splitlines(), 4)
            if "write" in granted.values():
                writers[job] = granted
        self.assertEqual(writers, {"commit": {"contents": "write"}})

    def test_checkouts_do_not_keep_credentials_unless_the_job_pushes(self) -> None:
        for name, text in WORKFLOWS.items():
            for job, block in jobs_of(text).items():
                if "actions/checkout@" not in block:
                    continue
                with self.subTest(workflow=name, job=job):
                    if (name, job) == ("bump.yml", "commit"):
                        self.assertNotIn("persist-credentials: false", block)
                    else:
                        self.assertIn("persist-credentials: false", block)

    def test_run_steps_never_interpolate_expressions(self) -> None:
        for name, text in WORKFLOWS.items():
            for script in run_scripts(text):
                with self.subTest(workflow=name, script=script.strip().splitlines()[:1]):
                    self.assertNotIn("${{", script)

    def test_only_the_automatic_token_is_ever_used(self) -> None:
        for name, text in WORKFLOWS.items():
            with self.subTest(workflow=name):
                self.assertEqual(set(re.findall(r"secrets\.([A-Za-z0-9_]+)", text)) - {"GITHUB_TOKEN"}, set())
                self.assertNotIn("pull_request_target", text)

    def test_a_bump_is_published_only_after_validation_and_never_on_a_dry_run(self) -> None:
        jobs = jobs_of(WORKFLOWS["bump.yml"])
        self.assertEqual(list(jobs), ["prepare", "validate", "commit"])
        self.assertRegex(jobs["validate"], r"needs:\s*prepare\b")
        self.assertRegex(jobs["commit"], r"needs:\s*\[\s*prepare,\s*validate\s*\]")
        for job in ("validate", "commit"):
            with self.subTest(job=job):
                self.assertRegex(jobs[job], r"needs\.prepare\.outputs\.changed == 'true'")
                self.assertIn("inputs.dry_run != true", jobs[job])
        self.assertIn("github.ref == 'refs/heads/main'", jobs["commit"])

    def test_both_mac_architectures_are_validated(self) -> None:
        for name in ("ci.yml", "bump.yml"):
            with self.subTest(workflow=name):
                self.assertRegex(WORKFLOWS[name], r"os:\s*\[macos-15,\s*macos-15-intel\]")

    def test_bump_flags_exist_in_the_script(self) -> None:
        flags = re.findall(r"flags\+=\((--[a-z-]+)\)", WORKFLOWS["bump.yml"])
        self.assertEqual(sorted(flags), ["--dry-run", "--verify-current"])
        for flag in flags:
            bump_cask.parse_args([flag])


class ValidationScriptTests(unittest.TestCase):
    def run_script(self, *args: str) -> subprocess.CompletedProcess:
        env = {key: value for key, value in os.environ.items() if key != "GITHUB_ACTIONS"}
        env["PATH"] = "/usr/bin:/bin"  # nothing in here can install software, even if the guard were ever broken
        return subprocess.run(
            ["bash", str(REPO_ROOT / "scripts" / "ci-validate.sh"), *args],
            capture_output=True,
            text=True,
            env=env,
            check=False,
            timeout=60,
        )

    def test_it_refuses_to_run_outside_github_actions(self) -> None:
        for args in (("tap",), ("published",), ()):
            with self.subTest(args=args):
                proc = self.run_script(*args)
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stdout, "")
                self.assertIn("GitHub Actions", proc.stderr)

    def test_guard_comes_before_anything_else_happens(self) -> None:
        body = [line for line in VALIDATE_SCRIPT.splitlines() if line and not line.startswith("#")]
        self.assertEqual(body[0], "set -euo pipefail")
        self.assertIn("GITHUB_ACTIONS", body[1])

    def test_the_published_flow_runs_the_documented_commands_verbatim(self) -> None:
        for command in USER_COMMANDS:
            with self.subTest(command=command):
                self.assertIn(command, VALIDATE_SCRIPT)

    def test_the_script_never_launches_the_app(self) -> None:
        for line in VALIDATE_SCRIPT.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            with self.subTest(line=stripped):
                self.assertFalse(stripped.startswith(("open ", "osascript", "launchctl", "exec ")))
                self.assertIsNone(re.match(r'^"?[^ ]*/Contents/MacOS/Cairn"?(\s|$)', stripped))


class RepositoryTests(unittest.TestCase):
    def test_the_sparkle_key_is_pinned(self) -> None:
        self.assertEqual(bump_cask.read_pinned_key(REPO_ROOT / "keys" / "sparkle-public-ed-key.txt"), PINNED_KEY)
        self.assertIn(PINNED_KEY, README)

    def test_scratch_files_are_never_committed(self) -> None:
        ignored = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertIn(".scratch/", ignored)

    def test_license_and_updates_for_pinned_actions(self) -> None:
        license_text = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("Apache License", license_text)
        self.assertIn("Version 2.0", license_text)
        dependabot = (REPO_ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
        self.assertIn("package-ecosystem: github-actions", dependabot)

    def test_readme_documents_the_commands_ci_exercises(self) -> None:
        for command in USER_COMMANDS:
            with self.subTest(command=command):
                self.assertIn(command, README)
        for phrase in ("Open Anyway", "not notarized", "python3 -m unittest", "SHA256SUMS", "pkeyutl -verify -rawin"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, README)


if __name__ == "__main__":
    unittest.main()
