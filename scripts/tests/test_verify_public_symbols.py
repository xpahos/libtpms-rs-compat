import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import verify_public_symbols as v

REPO = pathlib.Path(__file__).resolve().parents[2]
REFERENCE_SYMS = REPO / "libtpms" / "src" / "libtpms.syms"

SAMPLE_SYMS = """\
# comment
LIBTPMS_0.5.1 {
    global:
\tTPM_Free;
\tTPM_Malloc;
    local:
\t*;
};

LIBTPMS_0.6.0 {
    global:
\tTPMLIB_GetInfo; # trailing comment
    local:
\t*;
} LIBTPMS_0.5.1;
"""
SAMPLE_REQUIRED = ["TPM_Free", "TPM_Malloc", "TPMLIB_GetInfo"]


def macho_nm(names):
    return "".join(
        "00000000000%05x T _%s\n" % (index, name)
        for index, name in enumerate(names)
    ) + "                 U _malloc\n"


def elf_nm(names):
    return "".join(
        "00000000000%05x T %s@@LIBTPMS_0.5.1\n" % (index, name)
        for index, name in enumerate(names)
    )


class VersionScriptTests(unittest.TestCase):
    def test_globals_of_every_section(self):
        self.assertEqual(v.parse_version_script(SAMPLE_SYMS), SAMPLE_REQUIRED)

    def test_reference_lists_28_public_symbols(self):
        symbols = v.parse_version_script(REFERENCE_SYMS.read_text())
        self.assertEqual(len(symbols), 28)
        for name in ("TPM_Malloc", "TPM_Realloc", "TPM_Free",
                     "TPMLIB_SetProfile", "TPM_IO_TpmEstablished_Reset"):
            self.assertIn(name, symbols)
        self.assertNotIn("*", symbols)

    def test_unexpected_entry_is_an_error(self):
        with self.assertRaises(ValueError):
            v.parse_version_script("V {\n global:\n  TPM_*;\n};\n")


class NmParsingTests(unittest.TestCase):
    def test_macho_leading_underscore(self):
        output = macho_nm(SAMPLE_REQUIRED)
        self.assertEqual(v.missing_symbols(output, SAMPLE_REQUIRED, True), [])

    def test_macho_name_without_underscore_does_not_count(self):
        output = "0000000000001000 T TPM_Free\n"
        self.assertEqual(v.missing_symbols(output, ["TPM_Free"], True),
                         ["TPM_Free"])

    def test_elf_version_suffixes(self):
        output = elf_nm(["TPM_Free"]) + \
            "0000000000002000 T TPM_Malloc@LIBTPMS_0.5.1\n" + \
            "0000000000003000 T TPMLIB_GetInfo\n"
        self.assertEqual(v.missing_symbols(output, SAMPLE_REQUIRED, False), [])

    def test_elf_name_keeps_leading_underscore(self):
        output = "0000000000001000 T _TPM_Free\n"
        self.assertEqual(v.missing_symbols(output, ["TPM_Free"], False),
                         ["TPM_Free"])

    def test_undefined_and_local_symbols_do_not_count(self):
        output = (
            "                 U _TPM_Free\n"
            "0000000000001000 t _TPM_Malloc\n"
            "                 w _TPMLIB_GetInfo\n"
        )
        self.assertEqual(v.missing_symbols(output, SAMPLE_REQUIRED, True),
                         SAMPLE_REQUIRED)

    def test_extra_exports_are_allowed(self):
        output = macho_nm(SAMPLE_REQUIRED + ["rust_extra_symbol"])
        self.assertEqual(v.missing_symbols(output, SAMPLE_REQUIRED, True), [])


class CommandLineTests(unittest.TestCase):
    def _run(self, tmp, nm_stdout, fmt="macho", symbols=None):
        (tmp / "nm-output.txt").write_text(nm_stdout)
        nm_stub = tmp / "nm"
        nm_stub.write_text("#!/bin/sh\ncat '%s'\n" % (tmp / "nm-output.txt"))
        nm_stub.chmod(0o755)
        library = tmp / "libtpms.so"
        library.write_text("")
        return subprocess.run(
            [sys.executable, str(pathlib.Path(v.__file__)),
             "--symbols", str(symbols or REFERENCE_SYMS),
             "--library", str(library),
             "--format", fmt,
             "--nm", str(nm_stub)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

    def reference(self):
        return v.parse_version_script(REFERENCE_SYMS.read_text())

    def test_complete_exports_pass(self):
        for fmt, render in (("macho", macho_nm), ("elf", elf_nm)):
            with self.subTest(fmt=fmt), tempfile.TemporaryDirectory() as raw:
                result = self._run(pathlib.Path(raw), render(self.reference()),
                                   fmt)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("verify-public-symbols: OK (28 symbols",
                              result.stdout)

    def test_each_missing_symbol_is_reported(self):
        required = self.reference()
        for macho, render in ((True, macho_nm), (False, elf_nm)):
            for removed in required:
                with self.subTest(macho=macho, removed=removed):
                    present = [name for name in required if name != removed]
                    self.assertEqual(
                        v.missing_symbols(render(present), required, macho),
                        [removed],
                    )

    def test_missing_symbol_fails_the_command(self):
        present = [name for name in self.reference() if name != "TPM_Realloc"]
        for fmt, render in (("macho", macho_nm), ("elf", elf_nm)):
            with self.subTest(fmt=fmt), tempfile.TemporaryDirectory() as raw:
                result = self._run(pathlib.Path(raw), render(present), fmt)
                self.assertEqual(result.returncode, 1)
                self.assertIn(
                    "does not export public libtpms symbol TPM_Realloc\n",
                    result.stderr,
                )
                self.assertIn("1 of 28 public symbols", result.stderr)
                self.assertNotIn("OK", result.stdout)

    @unittest.skipUnless(shutil.which("cc") and shutil.which("nm"),
                         "needs cc and nm")
    def test_real_shared_library_missing_symbol(self):
        present = [name for name in self.reference() if name != "TPM_Free"]
        suffix = ".dylib" if sys.platform == "darwin" else ".so"
        with tempfile.TemporaryDirectory() as raw:
            tmp = pathlib.Path(raw)
            source = tmp / "partial.c"
            source.write_text("".join("void %s(void) {}\n" % name
                                      for name in present))
            library = tmp / ("libpartial" + suffix)
            subprocess.run(["cc", "-shared", "-fPIC", "-o", str(library),
                            str(source)], check=True)
            result = subprocess.run(
                [sys.executable, str(pathlib.Path(v.__file__)),
                 "--symbols", str(REFERENCE_SYMS),
                 "--library", str(library)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertIn("does not export public libtpms symbol TPM_Free\n",
                          result.stderr)
            self.assertIn("1 of 28 public symbols", result.stderr)

    def test_nm_failure_fails(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = pathlib.Path(raw)
            nm_stub = tmp / "nm"
            nm_stub.write_text("#!/bin/sh\necho broken >&2\nexit 3\n")
            nm_stub.chmod(0o755)
            result = subprocess.run(
                [sys.executable, str(pathlib.Path(v.__file__)),
                 "--symbols", str(REFERENCE_SYMS),
                 "--library", str(tmp / "missing.so"),
                 "--nm", str(nm_stub)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("broken", result.stderr)

    def test_empty_symbol_list_fails(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = pathlib.Path(raw)
            symbols = tmp / "empty.syms"
            symbols.write_text("V {\n local:\n  *;\n};\n")
            result = self._run(tmp, macho_nm(self.reference()),
                               symbols=symbols)
            self.assertEqual(result.returncode, 1)
            self.assertIn("lists no global symbols", result.stderr)


if __name__ == "__main__":
    unittest.main()
