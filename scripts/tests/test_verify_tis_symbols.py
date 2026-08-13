import pathlib
import subprocess
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import verify_tis_symbols as v


MACHO_EXPORTS_ALL = "\n".join(
    "000000000001%02x0 T _%s" % (i, name)
    for i, name in enumerate(v.REQUIRED_TIS_SYMBOLS)
) + "\n0000000000010000 T _TPMLIB_MainInit\n"

ELF_EXPORTS_ALL = "\n".join(
    "000000000001%02x0 T %s" % (i, name)
    for i, name in enumerate(v.REQUIRED_TIS_SYMBOLS)
) + "\n0000000000010000 T TPMLIB_MainInit\n"

MACHO_DYNAMIC_LOOKUP = (
    "                 (undefined) external _TPM_IO_Hash_Start "
    "(dynamically looked up)\n"
    "                 (undefined) external _TPMLIB_MainInit (from libtpms)\n"
)

MACHO_RESOLVED = (
    "                 (undefined) external _TPM_IO_Hash_Start (from libtpms)\n"
    "                 (undefined) external _TPMLIB_MainInit (from libtpms)\n"
)


class ExportParsingTests(unittest.TestCase):
    def test_all_macho_exports_present(self):
        self.assertEqual(v.missing_exports(MACHO_EXPORTS_ALL), [])

    def test_all_elf_exports_present(self):
        self.assertEqual(v.missing_exports(ELF_EXPORTS_ALL), [])

    def test_missing_symbol_is_named(self):
        partial = "\n".join(
            line
            for line in MACHO_EXPORTS_ALL.splitlines()
            if "TPM_IO_Hash_End" not in line
        )
        self.assertEqual(v.missing_exports(partial), ["TPM_IO_Hash_End"])

    def test_empty_output_reports_every_symbol(self):
        self.assertEqual(
            v.missing_exports(""), list(v.REQUIRED_TIS_SYMBOLS)
        )

    def test_undefined_entries_do_not_count_as_exports(self):
        undefined = "\n".join(
            "                 U _%s" % name for name in v.REQUIRED_TIS_SYMBOLS
        )
        self.assertEqual(
            v.missing_exports(undefined), list(v.REQUIRED_TIS_SYMBOLS)
        )


class DynamicLookupTests(unittest.TestCase):
    def test_dynamic_lookup_is_detected(self):
        self.assertEqual(
            v.dynamic_lookups(MACHO_DYNAMIC_LOOKUP), ["TPM_IO_Hash_Start"]
        )

    def test_resolved_symbols_pass(self):
        self.assertEqual(v.dynamic_lookups(MACHO_RESOLVED), [])

    def test_unrelated_dynamic_lookups_are_ignored(self):
        output = (
            "                 (undefined) external _optional_host_hook "
            "(dynamically looked up)\n"
        )
        self.assertEqual(v.dynamic_lookups(output), [])


class CommandLineTests(unittest.TestCase):
    def _run(self, tmp, nm_stdout, argv_extra=()):
        nm_stub = tmp / "nm"
        nm_stub.write_text(
            "#!/bin/sh\ncat %s\n" % (tmp / "nm-output.txt")
        )
        nm_stub.chmod(0o755)
        (tmp / "nm-output.txt").write_text(nm_stdout)
        library = tmp / "libtpms.dylib"
        library.write_text("")
        return subprocess.run(
            [
                sys.executable,
                str(pathlib.Path(v.__file__)),
                "--library",
                str(library),
                "--format",
                "macho",
                "--nm",
                str(nm_stub),
                *argv_extra,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_cli_fails_and_names_the_missing_symbol(self):
        import tempfile

        with tempfile.TemporaryDirectory() as raw:
            tmp = pathlib.Path(raw)
            partial = "\n".join(
                line
                for line in MACHO_EXPORTS_ALL.splitlines()
                if "TPM_IO_TpmEstablished_Reset" not in line
            )
            result = self._run(tmp, partial)
            self.assertEqual(result.returncode, 1)
            self.assertIn("TPM_IO_TpmEstablished_Reset", result.stderr)

    def test_cli_passes_with_complete_exports(self):
        import tempfile

        with tempfile.TemporaryDirectory() as raw:
            tmp = pathlib.Path(raw)
            result = self._run(tmp, MACHO_EXPORTS_ALL)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("verify-tis-symbols: OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
