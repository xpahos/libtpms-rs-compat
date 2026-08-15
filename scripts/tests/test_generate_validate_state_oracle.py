import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import generate_validate_state_oracle as g


VENDORED = b"vendored-digest"
CFLAGS = ["-I/opt/openssl/include"]
LIBS = ["-L/opt/openssl/lib", "-lcrypto"]

GIT_IDENTITY = [
    "-c",
    "user.name=oracle test",
    "-c",
    "user.email=oracle@example.invalid",
    "-c",
    "commit.gpgsign=false",
]


def settings(environment=None, cflags=None, libs=None, identity="cc (probe) 1.2.3"):
    return g.build_settings(
        CFLAGS if cflags is None else cflags,
        LIBS if libs is None else libs,
        environment={} if environment is None else environment,
        identity=identity,
    )


def fingerprint(environment, cflags=None, libs=None, vendored=VENDORED, identity="cc (probe) 1.2.3"):
    return g.fingerprint(
        g.build_inputs(settings(environment, cflags, libs, identity)), vendored
    )


def git(repository, *args):
    return subprocess.run(
        ["git", "-C", str(repository), *GIT_IDENTITY, *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def commit(repository, name, content):
    (repository / name).write_text(content)
    git(repository, "add", name)
    git(repository, "commit", "-m", f"add {name}")
    return git(repository, "rev-parse", "HEAD")


class BuildFingerprintTest(unittest.TestCase):
    def test_identical_inputs_are_deterministic(self):
        environment = {"CC": "clang", "CFLAGS": "-O2"}
        self.assertEqual(fingerprint(environment), fingerprint(dict(environment)))

    def test_every_inherited_build_setting_changes_the_fingerprint(self):
        base = {"CC": "clang", "CPPFLAGS": "-DA", "CFLAGS": "-O2", "LDFLAGS": "-L/a"}
        baseline = fingerprint(base)
        for key in g.BUILD_ENVIRONMENT_KEYS:
            changed = dict(base)
            changed[key] = base[key] + "x"
            self.assertNotEqual(baseline, fingerprint(changed), f"{key} was ignored")

    def test_unset_and_empty_settings_agree(self):
        self.assertEqual(fingerprint({"CFLAGS": ""}), fingerprint({}))

    def test_compiler_identity_changes_the_fingerprint(self):
        self.assertNotEqual(
            fingerprint({}, identity="cc 1.0"), fingerprint({}, identity="cc 2.0")
        )

    def test_quoting_variants_of_the_same_flags_agree(self):
        self.assertEqual(
            fingerprint({"CFLAGS": "-DA   -DB"}), fingerprint({"CFLAGS": "-DA -DB"})
        )
        self.assertNotEqual(
            fingerprint({"CFLAGS": '-DX="a b"'}), fingerprint({"CFLAGS": "-DX=a -DB=b"})
        )

    def test_compound_compiler_commands_change_the_fingerprint(self):
        self.assertNotEqual(
            fingerprint({"CC": "clang"}), fingerprint({"CC": "ccache clang"})
        )

    def test_detected_openssl_flags_change_the_fingerprint(self):
        baseline = fingerprint({})
        self.assertNotEqual(baseline, fingerprint({}, cflags=["-I/other/include"]))
        self.assertNotEqual(baseline, fingerprint({}, libs=["-L/other/lib", "-lcrypto"]))

    def test_configure_arguments_are_covered(self):
        baseline = fingerprint({})
        original = g.CONFIGURE_ARGS
        g.CONFIGURE_ARGS = [*original, "--enable-debug"]
        try:
            self.assertNotEqual(baseline, fingerprint({}))
        finally:
            g.CONFIGURE_ARGS = original
        self.assertEqual(baseline, fingerprint({}))

    def test_vendored_sources_change_the_fingerprint(self):
        self.assertNotEqual(fingerprint({}), fingerprint({}, vendored=b"other-digest"))

    def test_fingerprint_is_a_short_hex_directory_component(self):
        value = fingerprint({})
        self.assertEqual(len(value), 16)
        self.assertTrue(all(character in "0123456789abcdef" for character in value))


class VendoredFingerprintTest(unittest.TestCase):
    """Exercises a throwaway repository; the real submodule is never touched."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repository = pathlib.Path(self.tmp.name) / "libtpms"
        self.repository.mkdir()
        git(self.repository, "init", "--quiet")
        self.first = commit(self.repository, "source.c", "int first(void);\n")
        self.second = commit(self.repository, "more.c", "int second(void);\n")

    def checkout(self, revision):
        git(self.repository, "checkout", "--quiet", revision)

    def test_the_same_checkout_is_deterministic(self):
        self.assertEqual(
            g.vendored_fingerprint(self.repository),
            g.vendored_fingerprint(self.repository),
        )

    def test_the_checked_out_revision_is_the_repository_head(self):
        self.assertEqual(g.vendored_revision(self.repository), self.second)
        self.checkout(self.first)
        self.assertEqual(g.vendored_revision(self.repository), self.first)

    def test_a_different_checked_out_revision_changes_the_fingerprint(self):
        at_second = g.vendored_fingerprint(self.repository)
        self.checkout(self.first)
        at_first = g.vendored_fingerprint(self.repository)
        self.assertNotEqual(at_second, at_first)
        self.checkout(self.second)
        self.assertEqual(at_second, g.vendored_fingerprint(self.repository))

    def test_the_fingerprint_ignores_any_parent_gitlink(self):
        parent = pathlib.Path(self.tmp.name) / "parent"
        parent.mkdir()
        git(parent, "init", "--quiet")
        (parent / "keep").write_text("parent\n")
        git(parent, "add", "keep")
        git(parent, "commit", "-m", "parent")
        recorded = subprocess.run(
            ["git", "-C", str(parent), "rev-parse", "HEAD:libtpms"],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(recorded.returncode, 0, "the parent records no gitlink")

        at_second = g.vendored_fingerprint(self.repository)
        self.checkout(self.first)
        self.assertNotEqual(at_second, g.vendored_fingerprint(self.repository))

    def test_modified_tracked_files_change_the_fingerprint(self):
        clean = g.vendored_fingerprint(self.repository)
        (self.repository / "source.c").write_text("int first(void); /* edited */\n")
        dirty = g.vendored_fingerprint(self.repository)
        self.assertNotEqual(clean, dirty)
        (self.repository / "source.c").write_text("int first(void);\n")
        self.assertEqual(clean, g.vendored_fingerprint(self.repository))

    def test_untracked_files_change_the_fingerprint(self):
        clean = g.vendored_fingerprint(self.repository)
        (self.repository / "extra.c").write_text("int extra(void);\n")
        self.assertNotEqual(clean, g.vendored_fingerprint(self.repository))

    def test_deleted_files_change_the_fingerprint(self):
        clean = g.vendored_fingerprint(self.repository)
        (self.repository / "source.c").unlink()
        self.assertNotEqual(clean, g.vendored_fingerprint(self.repository))

    def test_a_renamed_file_changes_the_fingerprint(self):
        clean = g.vendored_fingerprint(self.repository)
        git(self.repository, "mv", "source.c", "renamed.c")
        renamed = g.vendored_fingerprint(self.repository)
        self.assertNotEqual(clean, renamed)
        codes = [code for code, _, _ in g.status_entries(g.vendored_status(self.repository))]
        self.assertTrue(any(code.startswith("R") for code in codes), codes)

    def test_editing_a_renamed_file_changes_the_fingerprint(self):
        git(self.repository, "mv", "source.c", "renamed.c")
        renamed = g.vendored_fingerprint(self.repository)
        (self.repository / "renamed.c").write_text("int first(void); /* edited */\n")
        edited = g.vendored_fingerprint(self.repository)
        self.assertNotEqual(renamed, edited)
        (self.repository / "renamed.c").write_text("int first(void); /* edited twice */\n")
        self.assertNotEqual(edited, g.vendored_fingerprint(self.repository))

    def test_repeated_edits_of_one_dirty_file_keep_changing_the_fingerprint(self):
        seen = set()
        for revision in range(4):
            (self.repository / "source.c").write_text(f"int first(void); /* {revision} */\n")
            seen.add(g.vendored_fingerprint(self.repository))
        self.assertEqual(len(seen), 4, "an unchanged status line masked the edits")

    def test_paths_containing_spaces_are_handled(self):
        clean = g.vendored_fingerprint(self.repository)
        spaced = self.repository / "a source file.c"
        spaced.write_text("int spaced(void);\n")
        untracked = g.vendored_fingerprint(self.repository)
        self.assertNotEqual(clean, untracked)
        paths = [path for _, path, _ in g.status_entries(g.vendored_status(self.repository))]
        self.assertIn("a source file.c", paths)

        git(self.repository, "add", "a source file.c")
        git(self.repository, "commit", "-m", "add spaced")
        committed = g.vendored_fingerprint(self.repository)
        spaced.write_text("int spaced(void); /* edited */\n")
        self.assertNotEqual(committed, g.vendored_fingerprint(self.repository))

    def test_a_renamed_path_with_spaces_records_both_paths(self):
        git(self.repository, "mv", "source.c", "renamed source.c")
        entries = g.status_entries(g.vendored_status(self.repository))
        renames = [entry for entry in entries if entry[0].startswith("R")]
        self.assertEqual(len(renames), 1, entries)
        _, path, origin = renames[0]
        self.assertEqual(path, "renamed source.c")
        self.assertEqual(origin, "source.c")

    def test_a_non_repository_is_handled_deterministically(self):
        plain = pathlib.Path(self.tmp.name) / "plain"
        plain.mkdir()
        self.assertEqual(g.vendored_revision(plain), "unknown-revision")
        self.assertIsNone(g.vendored_status(plain))
        self.assertEqual(g.vendored_fingerprint(plain), g.vendored_fingerprint(plain))
        self.assertNotEqual(g.vendored_fingerprint(plain), g.vendored_fingerprint(self.repository))


class StatusEntriesTest(unittest.TestCase):
    def test_plain_records_are_parsed(self):
        self.assertEqual(
            g.status_entries(" M src/a.c\0?? new file.c\0"),
            [(" M", "src/a.c", ""), ("??", "new file.c", "")],
        )

    def test_rename_records_carry_the_original_path(self):
        self.assertEqual(
            g.status_entries("R  new.c\0old.c\0 M other.c\0"),
            [(" M", "other.c", ""), ("R ", "new.c", "old.c")],
        )

    def test_copy_records_carry_the_source_path(self):
        self.assertEqual(g.status_entries("C  copy.c\0origin.c\0"), [("C ", "copy.c", "origin.c")])

    def test_records_are_sorted_deterministically(self):
        forward = g.status_entries(" M b.c\0 M a.c\0")
        reverse = g.status_entries(" M a.c\0 M b.c\0")
        self.assertEqual(forward, reverse)

    def test_an_empty_status_has_no_entries(self):
        self.assertEqual(g.status_entries(""), [])


class CompilerCommandTest(unittest.TestCase):
    def test_a_simple_command(self):
        self.assertEqual(g.compiler_command("cc"), ["cc"])

    def test_a_compound_command(self):
        self.assertEqual(g.compiler_command("ccache clang"), ["ccache", "clang"])
        self.assertEqual(
            g.compiler_command("clang -target arm64-apple-darwin"),
            ["clang", "-target", "arm64-apple-darwin"],
        )

    def test_quoted_arguments_are_preserved(self):
        self.assertEqual(
            g.compiler_command('clang -DGREETING="hello world"'),
            ["clang", "-DGREETING=hello world"],
        )

    def test_an_empty_value_is_rejected(self):
        for value in ("", "   "):
            with self.assertRaises(SystemExit) as raised:
                g.compiler_command(value)
            self.assertIn("CC is empty", str(raised.exception))

    def test_a_malformed_value_is_rejected(self):
        with self.assertRaises(SystemExit) as raised:
            g.compiler_command('clang -DX="unterminated')
        self.assertIn("cannot parse CC", str(raised.exception))

    def test_a_missing_compiler_is_reported_clearly(self):
        with self.assertRaises(SystemExit) as raised:
            g.compiler_identity(["definitely-not-a-compiler-42"])
        self.assertIn("cannot run the compiler", str(raised.exception))

    def test_a_real_compiler_identity_is_captured(self):
        identity = g.compiler_identity(g.compiler_command("cc"))
        self.assertTrue(identity.strip(), "the probe captured no version output")
        self.assertEqual(identity, g.compiler_identity(["cc"]))


INHERITED = {
    "CC": "ccache clang -target arm64-apple-darwin",
    "CPPFLAGS": "--sysroot=/some/sdk",
    "CFLAGS": "-arch x86_64 -fsanitize=address",
    "LDFLAGS": "-arch x86_64 -L/extra/lib",
}


class HarnessCommandTest(unittest.TestCase):
    def command(self, environment=None):
        return g.harness_command(settings(environment), "/tmp/build", "/tmp/oracle")

    def test_the_selected_compiler_drives_the_harness_build(self):
        command = self.command({"CC": "ccache clang"})
        self.assertEqual(command[:2], ["ccache", "clang"])
        self.assertIn(str(g.HARNESS), command)
        self.assertIn("/tmp/build/include", command)
        self.assertIn("/tmp/build/src/.libs/libtpms.a", command)

    def test_inherited_flags_reach_the_harness(self):
        command = self.command(INHERITED)
        for flag in ("--sysroot=/some/sdk", "-fsanitize=address", "-L/extra/lib"):
            self.assertIn(flag, command, f"{flag} never reached the harness")
        self.assertEqual(command.count("-arch"), 2, "CFLAGS and LDFLAGS both carry -arch")

    def test_detected_flags_appear_exactly_once(self):
        command = self.command(INHERITED)
        for flag in [*CFLAGS, *LIBS]:
            self.assertEqual(command.count(flag), 1, f"{flag} was repeated")

    def test_compiler_options_are_not_duplicated(self):
        command = self.command(INHERITED)
        self.assertEqual(command.count("-target"), 1)
        self.assertEqual(command.count("arm64-apple-darwin"), 1)
        self.assertEqual(command.count("ccache"), 1)

    def test_quoted_flag_values_stay_one_argument(self):
        command = self.command({"CPPFLAGS": '-DGREETING="hello world"'})
        self.assertIn("-DGREETING=hello world", command)

    def test_malformed_flags_are_rejected_clearly(self):
        with self.assertRaises(SystemExit) as raised:
            self.command({"CFLAGS": '-DX="unterminated'})
        self.assertIn("cannot parse CFLAGS", str(raised.exception))

    def test_compiler_flags_precede_inputs_and_linker_flags(self):
        command = self.command(INHERITED)
        self.assertLess(command.index("--sysroot=/some/sdk"), command.index(str(g.HARNESS)))
        self.assertLess(
            command.index("/tmp/build/src/.libs/libtpms.a"), command.index("-L/extra/lib")
        )
        self.assertLess(command.index("-L/extra/lib"), command.index("-lcrypto"))

    def test_the_vendored_environment_carries_the_same_inputs_once(self):
        environment = g.build_environment(settings(INHERITED), environment=INHERITED)
        self.assertEqual(environment["CC"], "ccache clang -target arm64-apple-darwin")
        self.assertEqual(
            environment["CPPFLAGS"], "-I/opt/openssl/include --sysroot=/some/sdk"
        )
        self.assertEqual(
            environment["CFLAGS"], "-I/opt/openssl/include -arch x86_64 -fsanitize=address"
        )
        self.assertEqual(
            environment["LDFLAGS"], "-L/opt/openssl/lib -arch x86_64 -L/extra/lib"
        )


if __name__ == "__main__":
    unittest.main()
