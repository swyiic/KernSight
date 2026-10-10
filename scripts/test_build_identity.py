#!/usr/bin/env python3
"""Exercise the actual dependency-free build.rs, including Cargo cache invalidation."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "crates/ksight-core/build.rs"


class BuildIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ksight-build-identity-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.core = self.root / "crates/ksight-core"
        (self.core / "src").mkdir(parents=True)
        self.env = os.environ.copy()
        for key in ("KERNSIGHT_BUILD_GIT_COMMIT", "KERNSIGHT_BUILD_GIT_DIRTY", "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
            self.env.pop(key, None)
        self.env["CARGO_TARGET_DIR"] = str(Path(self.temp.name) / "target")
        self.cargo = shutil.which("cargo")
        self.root.joinpath("Cargo.toml").write_text('[workspace]\nmembers = ["crates/ksight-core"]\nresolver = "2"\n')
        self.core.joinpath("Cargo.toml").write_text('[package]\nname = "identity-fixture"\nversion = "0.2.12"\nedition = "2021"\n')
        shutil.copyfile(SCRIPT, self.core / "build.rs")
        self.core.joinpath("src/main.rs").write_text('fn main() { println!("{}|{}|{}|{}", env!("KERNSIGHT_BUILD_VERSION"), env!("KERNSIGHT_GIT_COMMIT"), env!("KERNSIGHT_GIT_DIRTY"), env!("KERNSIGHT_BUILD_IDENTITY_SOURCE")); }\n')
        self.root.joinpath("README.md").write_text("documentation\n")
        self.root.joinpath("Makefile").write_text("# build fixture\n")
        self.root.joinpath("rust-toolchain.toml").write_text('[toolchain]\nchannel = "stable"\n')
        self.root.joinpath(".gitignore").write_text("/target/\n")
        # Match the real checkout: every source-input directory has a tracked anchor.
        for directory in (".cargo", "bpf", "native", "android", "rules", "xtask", "scripts"):
            folder = self.root / directory
            folder.mkdir()
            folder.joinpath(".gitkeep").write_text("tracked input directory\n")
        self.root.joinpath("crates/helper.rs").write_text("// input from another crate\n")
        self.run_command(self.cargo, "generate-lockfile", "--offline")
        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "Build Identity Test")
        self.git("config", "user.email", "build-test@example.invalid")
        self.git("add", ".")
        self.git("commit", "-m", "fixture")
        self.sha = self.git("rev-parse", "HEAD").strip()

    def run_command(self, *args, env=None, check=True):
        result = subprocess.run(args, cwd=self.root, env=env or self.env, text=True, capture_output=True)
        if check and result.returncode:
            self.fail(f"{args}: {result.stdout}\n{result.stderr}")
        return result

    def git(self, *args):
        return self.run_command("git", *args).stdout

    def build(self, env=None):
        result = self.run_command(self.cargo, "build", "--offline", env=env)
        binary = Path(self.env["CARGO_TARGET_DIR"]) / "debug/identity-fixture"
        return self.run_command(str(binary)).stdout.strip().split("|"), result.stderr

    def assert_identity(self, sha=None, dirty="false", source="git", env=None):
        sha = self.sha if sha is None else sha
        values, output = self.build(env)
        self.assertRegex(values[0], r"^0\.2\.12_[0-9a-f]{8}$")
        self.assertEqual(values[1:], [sha, dirty, source])
        return values[0]

    def test_clean_build_is_cached_and_documentation_is_not_dirty(self):
        first = self.assert_identity()
        second = self.assert_identity()
        self.assertNotEqual(first, second)
        self.root.joinpath("README.md").write_text("edited docs\n")
        self.root.joinpath("crates/notes.md").write_text("untracked notes\n")
        self.assert_identity()

    def test_worktree_index_and_untracked_source_changes(self):
        self.assert_identity()
        helper = self.root / "crates/helper.rs"
        original = helper.read_text()
        helper.write_text("// changed input\n")
        self.assert_identity(dirty="true")
        self.git("add", "crates/helper.rs")
        helper.write_text(original)  # only the staged contents remain different
        self.assert_identity(dirty="true")
        self.git("reset", "HEAD", "--", "crates/helper.rs")
        self.assert_identity()
        added = self.root / "crates/new_input.rs"
        added.write_text("// new source\n")
        self.assert_identity(dirty="true")
        added.unlink()
        self.assert_identity()

    def test_new_cargo_configuration_and_ignore_policy_invalidate_identity(self):
        self.assert_identity()
        config = self.root / ".cargo/config.toml"
        config.write_text("[build]\njobs = 1\n")
        self.assert_identity(dirty="true")
        config.unlink()
        self.assert_identity()
        ignore = self.root / ".gitignore"
        ignore.write_text("/target/\n/crates/ignored.rs\n")
        self.git("add", ".gitignore")
        self.git("commit", "-m", "ignore fixture")
        self.sha = self.git("rev-parse", "HEAD").strip()
        self.root.joinpath("crates/ignored.rs").write_text("// initially ignored\n")
        self.assert_identity()
        ignore.write_text("/target/\n")
        # No intervening Git commands: status can refresh index timestamps.
        self.assert_identity(dirty="true")

    def test_inherited_git_repository_and_index_overrides_are_ignored(self):
        other = Path(self.temp.name) / "other"
        subprocess.run(["git", "clone", str(self.root), str(other)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(other), "-c", "user.name=Other", "-c", "user.email=other@example.invalid", "commit", "--allow-empty", "-m", "other identity"], check=True, capture_output=True)
        env = {**self.env, "GIT_DIR": str(other / ".git"), "GIT_WORK_TREE": str(other), "GIT_COMMON_DIR": str(other / ".git"), "GIT_INDEX_FILE": str(other / ".git/index"), "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.worktree", "GIT_CONFIG_VALUE_0": str(other)}
        self.assert_identity(env=env)
        self.root.joinpath("crates/helper.rs").write_text("// modified actual source\n")
        self.assert_identity(dirty="true", env=env)

    def test_deleted_input_directory_remains_watched_until_restored(self):
        self.assert_identity()
        folder = self.root / "bpf"
        original = folder.joinpath(".gitkeep").read_text()
        shutil.rmtree(folder)
        self.assert_identity(dirty="true")
        self.assert_identity(dirty="true")
        folder.mkdir()
        folder.joinpath(".gitkeep").write_text(original)
        self.assert_identity()
        self.assertNotIn("Compiling identity-fixture", self.assert_identity())

    def test_head_ref_packed_refs_and_detached_head(self):
        self.assert_identity()
        self.git("commit", "--allow-empty", "-m", "new identity, same files")
        next_sha = self.git("rev-parse", "HEAD").strip()
        self.assert_identity(sha=next_sha)
        self.git("pack-refs", "--all", "--prune")
        self.assert_identity(sha=next_sha)
        self.git("update-ref", "refs/heads/main", self.sha)
        self.assert_identity()
        self.git("checkout", "--detach", next_sha)
        self.assert_identity(sha=next_sha)

    def test_linked_worktree_identity_and_ref_changes(self):
        linked = Path(self.temp.name) / "linked"
        self.git("worktree", "add", "-b", "linked", str(linked))
        self.root = linked
        self.assert_identity()
        self.git("commit", "--allow-empty", "-m", "linked identity")
        self.assert_identity(sha=self.git("rev-parse", "HEAD").strip())
        self.assertNotIn("Compiling identity-fixture", self.build()[1])

    def test_archive_does_not_borrow_ancestor_repository_identity(self):
        shutil.rmtree(self.root / ".git")
        # Make an unrelated enclosing repository to prove archives do not borrow it.
        parent = self.root.parent
        subprocess.run(["git", "init", str(parent)], check=True, capture_output=True)
        parent.joinpath("unrelated.txt").write_text("other repository\n")
        for args in (("config", "user.name", "Ancestor Test"), ("config", "user.email", "ancestor@example.invalid"), ("add", "unrelated.txt"), ("commit", "-m", "unrelated parent")):
            subprocess.run(["git", "-C", str(parent), *args], check=True, capture_output=True)
        self.assertEqual(len(self.git("rev-parse", "HEAD").strip()), 40)
        values, _ = self.build()
        self.assertRegex(values[0], r"^0\.2\.12_[0-9a-f]{8}$")
        self.assertEqual(values[1:], ["", "unknown", "unknown"])
        self.assertNotIn("Compiling identity-fixture", self.build()[1])

    def test_git_unavailable_and_explicit_release_override(self):
        # A small PATH shim makes only Git unavailable while Cargo/rustc keep working.
        shims = Path(self.temp.name) / "bin"
        shims.mkdir()
        fake_git = shims / "git"
        fake_git.write_text("#!/bin/sh\nexit 127\n")
        fake_git.chmod(0o755)
        env = {**self.env, "PATH": f"{shims}{os.pathsep}{self.env['PATH']}"}
        values = self.build(env)[0]
        self.assertRegex(values[0], r"^0\.2\.12_[0-9a-f]{8}$")
        self.assertEqual(values[1:], ["", "unknown", "unknown"])
        env.update(KERNSIGHT_BUILD_GIT_COMMIT=self.sha, KERNSIGHT_BUILD_GIT_DIRTY="false")
        self.assert_identity(source="override", env=env)
        self.assertNotIn("Compiling identity-fixture", self.build(env)[1])
        env["KERNSIGHT_BUILD_GIT_DIRTY"] = "true"
        self.assert_identity(dirty="true", source="override", env=env)

    def test_failed_dirty_probe_is_explicitly_unknown(self):
        shims = Path(self.temp.name) / "bin"
        shims.mkdir()
        fake_git = shims / "git"
        real_git = shutil.which("git")
        fake_git.write_text(f'#!/bin/sh\nfor arg in "$@"; do [ "$arg" = status ] && exit 1; done\nexec "{real_git}" "$@"\n')
        fake_git.chmod(0o755)
        env = {**self.env, "PATH": f"{shims}{os.pathsep}{self.env['PATH']}"}
        values = self.build(env)[0]
        self.assertRegex(values[0], r"^0\.2\.12_[0-9a-f]{8}$")
        self.assertEqual(values[1:], [self.sha, "unknown", "git"])

    def test_invalid_or_incomplete_override_fails_explicitly(self):
        for commit, dirty in ((self.sha[:7], "false"), (self.sha, None), (None, "false"), (self.sha, "maybe")):
            env = self.env.copy()
            if commit is not None:
                env["KERNSIGHT_BUILD_GIT_COMMIT"] = commit
            if dirty is not None:
                env["KERNSIGHT_BUILD_GIT_DIRTY"] = dirty
            result = self.run_command(self.cargo, "build", "--offline", env=env, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("KERNSIGHT_BUILD_GIT_", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
