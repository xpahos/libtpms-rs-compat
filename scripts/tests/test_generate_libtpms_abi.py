"""Tests for scripts/generate_libtpms_abi.py."""

import contextlib
import importlib.util
import io
import os
import pathlib
import tempfile
import unittest

_SCRIPTS_DIR = pathlib.Path(__file__).resolve().parents[1]
_REPO_ROOT = _SCRIPTS_DIR.parent
_REAL_HEADER = _REPO_ROOT / "libtpms" / "include" / "libtpms" / "tpm_library.h"

_spec = importlib.util.spec_from_file_location(
    "generate_libtpms_abi", _SCRIPTS_DIR / "generate_libtpms_abi.py"
)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)


class GeneratorTestCase(unittest.TestCase):
    """Base helpers: run the generator pipeline over a synthetic header."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmpdir = pathlib.Path(self._tmp.name)

    def write_header(self, source, name="test_header.h"):
        path = self.tmpdir / name
        path.write_text(source, encoding="utf-8")
        return path

    def run_main(self, argv):
        """Run the CLI with captured output; returns (exit_code, out, err)."""
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            code = gen.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def collect(self, source):
        path = self.write_header(source)
        ast, real = gen.parse_header(str(path))
        return gen.collect_functions(ast, real)

    def render(self, source):
        return gen.render_rust(self.collect(source), "test_header.h")


class ParsingTests(GeneratorTestCase):
    def test_single_line_declaration(self):
        funcs = self.collect("uint32_t Foo(uint32_t x);\n")
        self.assertEqual(len(funcs), 1)
        self.assertEqual(funcs[0].name, "Foo")
        self.assertEqual(funcs[0].params, [("x", "u32")])
        self.assertEqual(funcs[0].ret, "u32")

    def test_multiline_declaration(self):
        funcs = self.collect(
            "TPM_RESULT Foo(unsigned char **respbuffer,\n"
            "               uint32_t *resp_size,\n"
            "               uint32_t command_size);\n"
        )
        self.assertEqual(len(funcs), 1)
        self.assertEqual(
            funcs[0].params,
            [
                ("respbuffer", "*mut *mut core::ffi::c_uchar"),
                ("resp_size", "*mut u32"),
                ("command_size", "u32"),
            ],
        )

    def test_pointer_argument(self):
        funcs = self.collect("void Foo(int *value);\n")
        self.assertEqual(funcs[0].params,
                         [("value", "*mut core::ffi::c_int")])

    def test_pointer_to_pointer_argument(self):
        funcs = self.collect("void Foo(unsigned char **data);\n")
        self.assertEqual(funcs[0].params,
                         [("data", "*mut *mut core::ffi::c_uchar")])

    def test_const_pointer_argument(self):
        funcs = self.collect("void Foo(const char *name);\n")
        self.assertEqual(funcs[0].params,
                         [("name", "*const core::ffi::c_char")])

    def test_void_pointer_arguments(self):
        funcs = self.collect("void Foo(void *a, const void *b);\n")
        self.assertEqual(
            funcs[0].params,
            [("a", "*mut core::ffi::c_void"),
             ("b", "*const core::ffi::c_void")],
        )

    def test_void_return_type(self):
        funcs = self.collect("void Foo(int fd);\n")
        self.assertIsNone(funcs[0].ret)
        rust = self.render("void Foo(int fd);\n")
        self.assertIn("fn Foo(fd: core::ffi::c_int) {", rust)
        self.assertNotIn("->", rust.split("fn Foo")[1].split("{")[0])

    def test_integer_return_types(self):
        funcs = self.collect("uint32_t A(void);\nint B(void);\n")
        self.assertEqual(funcs[0].ret, "u32")
        self.assertEqual(funcs[1].ret, "core::ffi::c_int")

    def test_void_parameter_list_means_no_params(self):
        funcs = self.collect("uint32_t Foo(void);\n")
        self.assertEqual(funcs[0].params, [])

    def test_typedef_based_types(self):
        funcs = self.collect(
            "TPM_RESULT Foo(TPM_BOOL flag, TPM_MODIFIER_INDICATOR *loc);\n"
        )
        self.assertEqual(funcs[0].ret, "TpmResult")
        self.assertEqual(
            funcs[0].params,
            [("flag", "TpmBool"), ("loc", "*mut TpmModifierIndicator")],
        )

    def test_local_typedef_enum_by_value(self):
        funcs = self.collect(
            "typedef enum TPMLIB_TPMVersion { A_V1, A_V2 } TPMLIB_TPMVersion;\n"
            "TPM_RESULT Foo(TPMLIB_TPMVersion ver);\n"
        )
        self.assertEqual(len(funcs), 1)
        self.assertEqual(funcs[0].params, [("ver", "TpmlibTpmVersion")])

    def test_enum_tag_by_value(self):
        funcs = self.collect(
            "enum TPMLIB_StateType { S_A = 1, S_B = 2 };\n"
            "TPM_RESULT Foo(enum TPMLIB_StateType st);\n"
        )
        self.assertEqual(funcs[0].params, [("st", "TpmlibStateType")])

    def test_opaque_struct_pointer(self):
        funcs = self.collect(
            "struct libtpms_callbacks { int sizeOfStruct; };\n"
            "TPM_RESULT Foo(struct libtpms_callbacks *cbs);\n"
        )
        self.assertEqual(funcs[0].params,
                         [("cbs", "*mut LibtpmsCallbacks")])

    def test_function_pointer_typedef_ignored(self):
        funcs = self.collect(
            "typedef TPM_RESULT (*my_callback)(unsigned char **data);\n"
            "uint32_t Foo(void);\n"
        )
        self.assertEqual([f.name for f in funcs], ["Foo"])

    def test_plain_typedef_ignored(self):
        funcs = self.collect(
            "typedef uint32_t MY_ALIAS;\n"
            "uint32_t Foo(void);\n"
        )
        self.assertEqual([f.name for f in funcs], ["Foo"])

    def test_static_function_ignored(self):
        funcs = self.collect(
            "static int helper(void);\n"
            "uint32_t Foo(void);\n"
        )
        self.assertEqual([f.name for f in funcs], ["Foo"])

    def test_macros_and_comments_invisible(self):
        funcs = self.collect(
            "/* a block comment\n   spanning lines */\n"
            "#define SOME_MACRO(X) \\\n"
            "    ((X) + 1)\n"
            "#define A_STRING \"-----TAG-----\"\n"
            "// line comment\n"
            "uint32_t Foo(void);\n"
        )
        self.assertEqual([f.name for f in funcs], ["Foo"])

    def test_cplusplus_extern_c_guard_stripped(self):
        funcs = self.collect(
            "#ifdef __cplusplus\n"
            'extern "C" {\n'
            "#endif\n"
            "uint32_t Foo(void);\n"
            "#ifdef __cplusplus\n"
            "}\n"
            "#endif\n"
        )
        self.assertEqual([f.name for f in funcs], ["Foo"])

    def test_unnamed_parameter_gets_synthetic_name(self):
        funcs = self.collect(
            "struct libtpms_callbacks { int sizeOfStruct; };\n"
            "TPM_RESULT Foo(struct libtpms_callbacks *);\n"
        )
        self.assertEqual(funcs[0].params,
                         [("arg0", "*mut LibtpmsCallbacks")])

    def test_rust_keyword_parameter_escaped(self):
        funcs = self.collect(
            "enum TPMLIB_BlobType { B_A };\n"
            "void Foo(enum TPMLIB_BlobType type);\n"
        )
        self.assertEqual(funcs[0].params, [("r#type", "TpmlibBlobType")])
        rust = gen.render_rust(funcs, "test_header.h")
        self.assertIn("r#type: TpmlibBlobType", rust)


class ErrorTests(GeneratorTestCase):
    def test_unsupported_type_reports_type_function_and_location(self):
        with self.assertRaises(gen.AbiError) as ctx:
            self.collect("void Foo(int a);\ndouble Bar(double x);\n")
        message = str(ctx.exception)
        self.assertIn("Bar", message)
        self.assertIn("double", message)
        self.assertIn("test_header.h", message)

    def test_unknown_enum_tag_rejected(self):
        with self.assertRaises(gen.AbiError) as ctx:
            self.collect("void Foo(enum SomeUnknownEnum e);\n")
        self.assertIn("SomeUnknownEnum", str(ctx.exception))

    def test_unknown_struct_tag_rejected(self):
        with self.assertRaises(gen.AbiError) as ctx:
            self.collect("void Foo(struct unknown_struct *p);\n")
        self.assertIn("unknown_struct", str(ctx.exception))

    def test_struct_by_value_rejected(self):
        with self.assertRaises(gen.AbiError) as ctx:
            self.collect(
                "struct libtpms_callbacks { int sizeOfStruct; };\n"
                "void Foo(struct libtpms_callbacks cbs);\n"
            )
        self.assertIn("by value", str(ctx.exception))

    def test_variadic_function_rejected(self):
        with self.assertRaises(gen.AbiError) as ctx:
            self.collect("void Foo(const char *fmt, ...);\n")
        self.assertIn("variadic", str(ctx.exception))

    def test_syntax_error_raises_parse_error(self):
        path = self.write_header("uint32_t Foo(uint32_t x;\n")
        with self.assertRaises(gen.ParseError):
            gen.parse_header(str(path))

    def test_unknown_typedef_fails_loudly(self):
        # An unknown type name is a syntax error for the parser (no such
        # typedef in scope), so nothing is silently guessed.
        path = self.write_header("some_unknown_t Foo(void);\n")
        with self.assertRaises((gen.ParseError, gen.AbiError)):
            ast, real = gen.parse_header(str(path))
            gen.collect_functions(ast, real)


class OutputTests(GeneratorTestCase):
    SOURCE = (
        "uint32_t Foo(const char *name, unsigned char **data);\n"
        "void Bar(int fd);\n"
    )

    def test_rendered_stub_shape(self):
        rust = self.render("uint32_t Foo(uint32_t x);\n")
        self.assertIn("// This file is automatically generated.", rust)
        self.assertIn("#![allow(non_snake_case)]", rust)
        self.assertIn("#[unsafe(no_mangle)]", rust)
        self.assertIn('pub unsafe extern "C" fn Foo(x: u32) -> u32 {', rust)
        self.assertIn("ffi_guard(|| crate::ffi::api::foo(x))", rust)
        self.assertIn("use crate::ffi::memory::ffi_guard;", rust)
        self.assertIn("use crate::ffi::types::*;", rust)
        self.assertIn("#![allow(clippy::missing_safety_doc)]", rust)

    def test_raw_pointer_call_is_explicitly_unsafe(self):
        rust = self.render("uint32_t Foo(const char *name);\n")
        self.assertIn(
            "ffi_guard(|| unsafe { crate::ffi::api::foo(name) })",
            rust,
        )

    def test_short_signature_stays_on_one_line(self):
        rust = self.render("uint32_t Foo(uint32_t x);\n")
        self.assertIn('pub unsafe extern "C" fn Foo(x: u32) -> u32 {', rust)

    def test_long_signature_wraps_one_param_per_line(self):
        rust = self.render(
            "TPM_RESULT TPMLIB_Process(unsigned char **respbuffer,\n"
            "    uint32_t *resp_size, uint32_t *respbufsize,\n"
            "    unsigned char *command, uint32_t command_size);\n"
        )
        self.assertIn(
            'pub unsafe extern "C" fn TPMLIB_Process(\n'
            "    respbuffer: *mut *mut core::ffi::c_uchar,\n"
            "    resp_size: *mut u32,\n"
            "    respbufsize: *mut u32,\n"
            "    command: *mut core::ffi::c_uchar,\n"
            "    command_size: u32,\n"
            ") -> TpmResult {",
            rust,
        )
        for line in rust.splitlines():
            self.assertLessEqual(len(line), gen.RUST_MAX_WIDTH)

    def test_rust_impl_names(self):
        cases = {
            "TPMLIB_GetVersion": "get_version",
            "TPMLIB_ChooseTPMVersion": "choose_tpm_version",
            "TPMLIB_MainInit": "main_init",
            "TPMLIB_VolatileAll_Store": "volatile_all_store",
            "TPMLIB_GetTPMProperty": "get_tpm_property",
            "TPMLIB_SetDebugFD": "set_debug_fd",
            "TPMLIB_WasManufactured": "was_manufactured",
            "Foo": "foo",
        }
        for c_name, rust_name in cases.items():
            self.assertEqual(gen.rust_impl_name(c_name), rust_name)

    def test_colliding_impl_names_are_rejected(self):
        funcs = self.collect(
            "void TPMLIB_MainInit(void);\nvoid MainInit(void);\n"
        )
        with self.assertRaises(gen.AbiError) as ctx:
            gen.render_rust(funcs, "test_header.h")
        self.assertIn("main_init", str(ctx.exception))

    def test_deterministic_output(self):
        first = self.render(self.SOURCE)
        second = self.render(self.SOURCE)
        self.assertEqual(first, second)

    def test_manifest_sorted_and_complete(self):
        funcs = self.collect("void Zeta(void);\nvoid Alpha(void);\n")
        manifest = gen.render_manifest(funcs)
        self.assertEqual(manifest, "Alpha\nZeta\n")

    def test_write_if_changed_skips_identical_content(self):
        out = self.tmpdir / "out.rs"
        self.assertTrue(gen.write_if_changed(str(out), "content\n"))
        stat_before = out.stat()
        self.assertFalse(gen.write_if_changed(str(out), "content\n"))
        stat_after = out.stat()
        self.assertEqual(stat_before.st_mtime_ns, stat_after.st_mtime_ns)
        self.assertTrue(gen.write_if_changed(str(out), "different\n"))

    def test_main_end_to_end_and_no_rewrite(self):
        header = self.write_header(self.SOURCE)
        out = self.tmpdir / "generated" / "abi.rs"
        manifest = self.tmpdir / "manifest.txt"
        argv = [
            "--header", str(header),
            "--output", str(out),
            "--manifest", str(manifest),
        ]
        code, stdout, _ = self.run_main(argv)
        self.assertEqual(code, 0)
        self.assertIn("updated (2 functions)", stdout)
        content = out.read_text(encoding="utf-8")
        self.assertIn('extern "C" fn Foo', content)
        self.assertEqual(manifest.read_text(encoding="utf-8"), "Bar\nFoo\n")
        mtime = out.stat().st_mtime_ns
        code, stdout, _ = self.run_main(argv)
        self.assertEqual(code, 0)
        self.assertIn("unchanged (2 functions)", stdout)
        self.assertEqual(out.stat().st_mtime_ns, mtime)

    def test_main_missing_header_fails(self):
        code, _, stderr = self.run_main(
            ["--header", str(self.tmpdir / "nope.h"),
             "--output", str(self.tmpdir / "out.rs")]
        )
        self.assertEqual(code, 1)
        self.assertIn("header not found", stderr)

    def test_main_unsupported_type_fails(self):
        header = self.write_header("double Bad(double x);\n")
        out = self.tmpdir / "out.rs"
        code, _, stderr = self.run_main(
            ["--header", str(header), "--output", str(out)]
        )
        self.assertEqual(code, 1)
        self.assertIn("function 'Bad'", stderr)
        self.assertIn("unsupported C type 'double'", stderr)
        self.assertIn("test_header.h:1", stderr)
        self.assertFalse(out.exists())


class FfiTypeCheckTests(GeneratorTestCase):
    HEADER = (
        "typedef enum TPMLIB_TPMVersion { V1, V2 } TPMLIB_TPMVersion;\n"
        "enum TPMLIB_StateType { S_A = 1 };\n"
        "struct libtpms_callbacks {\n"
        "    int sizeOfStruct;\n"
        "    TPM_RESULT (*tpm_io_getlocality)(TPM_MODIFIER_INDICATOR *loc,\n"
        "                                     uint32_t tpm_number);\n"
        "};\n"
        "TPM_RESULT Foo(TPMLIB_TPMVersion ver, struct libtpms_callbacks *cbs);\n"
        "TPM_BOOL Bar(enum TPMLIB_StateType st);\n"
    )
    # C type names the synthetic header defines or references (primitives
    # like int/uint32_t excluded).
    HEADER_TYPES = {
        "TPMLIB_TPMVersion", "TPMLIB_StateType", "libtpms_callbacks",
        "TPM_RESULT", "TPM_BOOL", "TPM_MODIFIER_INDICATOR",
    }
    MATCHING_FFI = (
        "pub type TpmResult = u32;\n"
        "pub type TpmBool = u8;\n"
        "pub type TpmModifierIndicator = u32;\n"
        "pub type TpmlibTpmVersion = core::ffi::c_int;\n"
        "pub type TpmlibStateType = core::ffi::c_int;\n"
        "#[repr(C)]\n"
        "pub struct LibtpmsCallbacks {\n"
        "    pub size_of_struct: core::ffi::c_int,\n"
        "    pub tpm_io_getlocality: Option<unsafe extern \"C\" fn(\n"
        "        *mut TpmModifierIndicator, u32\n"
        "    ) -> TpmResult>,\n"
        "}\n"
    )

    def write_ffi(self, source):
        path = self.tmpdir / "types.rs"
        path.write_text(source, encoding="utf-8")
        return str(path)

    def header_types(self, source):
        path = self.write_header(source)
        ast, real = gen.parse_header(str(path))
        return gen.collect_header_types(ast, real)

    def test_collect_header_types(self):
        self.assertEqual(self.header_types(self.HEADER), self.HEADER_TYPES)

    def test_collect_ffi_rust_types(self):
        path = self.write_ffi(self.MATCHING_FFI)
        self.assertEqual(
            gen.collect_ffi_rust_types(path),
            {"TpmResult", "TpmBool", "TpmModifierIndicator",
             "TpmlibTpmVersion", "TpmlibStateType", "LibtpmsCallbacks"},
        )

    def test_check_passes_when_types_match(self):
        path = self.write_ffi(self.MATCHING_FFI)
        errors = gen.check_ffi_types(self.header_types(self.HEADER), path)
        self.assertEqual(errors, [])

    def test_header_type_missing_from_ffi_detected(self):
        ffi = self.MATCHING_FFI.replace("pub type TpmBool = u8;\n", "")
        path = self.write_ffi(ffi)
        errors = gen.check_ffi_types(self.header_types(self.HEADER), path)
        self.assertEqual(len(errors), 1)
        self.assertIn("TpmBool", errors[0])
        self.assertIn("not declared", errors[0])

    def test_orphan_ffi_type_detected(self):
        path = self.write_ffi(self.MATCHING_FFI
                              + "pub type StaleLeftover = u64;\n")
        errors = gen.check_ffi_types(self.header_types(self.HEADER), path)
        self.assertEqual(len(errors), 1)
        self.assertIn("StaleLeftover", errors[0])
        self.assertIn("does not correspond", errors[0])

    def test_unmapped_header_type_detected(self):
        header_types = self.header_types(
            self.HEADER + "enum TPMLIB_BrandNew { N_A };\n"
        )
        path = self.write_ffi(self.MATCHING_FFI)
        errors = gen.check_ffi_types(header_types, path)
        self.assertEqual(len(errors), 1)
        self.assertIn("TPMLIB_BrandNew", errors[0])
        self.assertIn("mapping tables", errors[0])

    def test_main_check_ffi_types_mode(self):
        header = self.write_header(self.HEADER)
        good = self.write_ffi(self.MATCHING_FFI)
        code, stdout, _ = self.run_main(
            ["--header", str(header), "--check-ffi-types", good]
        )
        self.assertEqual(code, 0)
        self.assertIn("check-ffi-types: OK (6 C types, 1 struct layouts",
                      stdout)
        bad = self.tmpdir / "bad_ffi.rs"
        bad.write_text(self.MATCHING_FFI + "pub type Orphan = u8;\n",
                       encoding="utf-8")
        code, _, stderr = self.run_main(
            ["--header", str(header), "--check-ffi-types", str(bad)]
        )
        self.assertEqual(code, 1)
        self.assertIn("'Orphan'", stderr)
        self.assertIn("does not correspond to any type in the header",
                      stderr)

    def test_struct_layout_diff_reports_wrong_field_type(self):
        header = self.write_header(self.HEADER)
        ast, real = gen.parse_header(str(header))
        structs = gen.collect_header_structs(ast, real)
        bad = self.write_ffi(self.MATCHING_FFI.replace(
            "*mut TpmModifierIndicator, u32",
            "*const TpmModifierIndicator, u32",
        ))
        errors = gen.check_ffi_structs(structs, bad)
        self.assertEqual(len(errors), 1)
        self.assertIn("FFI struct layout mismatch", errors[0])
        self.assertIn("--- C struct libtpms_callbacks", errors[0])
        # The diff shows canonical spellings: aliases resolved to u32.
        self.assertIn("fn(*mut u32", errors[0])
        self.assertIn("fn(*const u32", errors[0])

    def test_struct_layout_diff_reports_missing_repr_c(self):
        header = self.write_header(self.HEADER)
        ast, real = gen.parse_header(str(header))
        structs = gen.collect_header_structs(ast, real)
        bad = self.write_ffi(self.MATCHING_FFI.replace("#[repr(C)]\n", ""))
        errors = gen.check_ffi_structs(structs, bad)
        self.assertEqual(len(errors), 1)
        self.assertIn("#[missing repr(C)]", errors[0])

    def test_struct_layout_diff_reports_field_order(self):
        header = self.write_header(self.HEADER)
        ast, real = gen.parse_header(str(header))
        structs = gen.collect_header_structs(ast, real)
        reordered = self.MATCHING_FFI.replace(
            "    pub size_of_struct: core::ffi::c_int,\n"
            "    pub tpm_io_getlocality:",
            "    pub tpm_io_getlocality:",
        ).replace(
            "    ) -> TpmResult>,\n"
            "}\n",
            "    ) -> TpmResult>,\n"
            "    pub size_of_struct: core::ffi::c_int,\n"
            "}\n",
        )
        bad = self.write_ffi(reordered)
        errors = gen.check_ffi_structs(structs, bad)
        self.assertEqual(len(errors), 1)
        self.assertIn("FFI struct layout mismatch", errors[0])

    def test_struct_layout_accepts_abi_equivalent_spellings(self):
        header = self.write_header(self.HEADER)
        ast, real = gen.parse_header(str(header))
        structs = gen.collect_header_structs(ast, real)
        # Same ABI, different spellings: aliases written out (TpmResult ->
        # u32, TpmModifierIndicator -> u32) and a primitive imported via
        # `use core::ffi::c_int` instead of path-qualified.
        equivalent = self.write_ffi(
            "pub type TpmResult = u32;\n"
            "pub type TpmBool = u8;\n"
            "pub type TpmModifierIndicator = u32;\n"
            "pub type TpmlibTpmVersion = core::ffi::c_int;\n"
            "pub type TpmlibStateType = core::ffi::c_int;\n"
            "#[repr(C)]\n"
            "pub struct LibtpmsCallbacks {\n"
            "    pub size_of_struct: c_int,\n"
            "    pub tpm_io_getlocality:\n"
            "        Option<unsafe extern \"C\" fn(*mut u32, u32) -> u32>,\n"
            "}\n"
        )
        self.assertEqual(gen.check_ffi_structs(structs, equivalent), [])

    def test_struct_layout_alias_cycle_is_reported(self):
        header = self.write_header(self.HEADER)
        ast, real = gen.parse_header(str(header))
        structs = gen.collect_header_structs(ast, real)
        cyclic = self.write_ffi(
            self.MATCHING_FFI.replace(
                "pub type TpmResult = u32;\n",
                "pub type TpmResult = TpmCycle;\n"
                "pub type TpmCycle = TpmResult;\n",
            )
        )
        with self.assertRaises(gen.AbiError) as ctx:
            gen.check_ffi_structs(structs, cyclic)
        self.assertIn("alias cycle", str(ctx.exception))


@unittest.skipUnless(_REAL_HEADER.is_file(),
                     "libtpms submodule not checked out")
class RealHeaderTests(GeneratorTestCase):
    EXPECTED = [
        "TPMLIB_GetVersion",
        "TPMLIB_ChooseTPMVersion",
        "TPMLIB_MainInit",
        "TPMLIB_Terminate",
        "TPMLIB_Process",
        "TPMLIB_VolatileAll_Store",
        "TPMLIB_CancelCommand",
        "TPMLIB_GetTPMProperty",
        "TPMLIB_GetInfo",
        "TPMLIB_RegisterCallbacks",
        "TPMLIB_DecodeBlob",
        "TPMLIB_SetDebugFD",
        "TPMLIB_SetDebugLevel",
        "TPMLIB_SetDebugPrefix",
        "TPMLIB_SetBufferSize",
        "TPMLIB_ValidateState",
        "TPMLIB_SetState",
        "TPMLIB_GetState",
        "TPMLIB_SetProfile",
        "TPMLIB_WasManufactured",
    ]

    def test_parses_all_public_functions_in_order(self):
        ast, real = gen.parse_header(str(_REAL_HEADER))
        funcs = gen.collect_functions(ast, real)
        self.assertEqual([f.name for f in funcs], self.EXPECTED)

    def test_real_ffi_types_module_matches_header(self):
        ffi_path = _REPO_ROOT / "src" / "ffi" / "types.rs"
        self.assertTrue(ffi_path.is_file())
        ast, real = gen.parse_header(str(_REAL_HEADER))
        header_types = gen.collect_header_types(ast, real)
        errors = gen.check_ffi_types(header_types, str(ffi_path))
        self.assertEqual(errors, [])

    def test_all_functions_appear_in_rendered_rust(self):
        ast, real = gen.parse_header(str(_REAL_HEADER))
        funcs = gen.collect_functions(ast, real)
        rust = gen.render_rust(funcs, "libtpms/include/libtpms/tpm_library.h")
        for name in self.EXPECTED:
            self.assertIn('pub unsafe extern "C" fn %s(' % name, rust)


if __name__ == "__main__":
    unittest.main()
