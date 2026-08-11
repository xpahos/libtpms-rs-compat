#!/usr/bin/env python3
"""Generate Rust C-ABI function stubs from the libtpms public header.

Parses ``libtpms/include/libtpms/tpm_library.h`` with pycparser (a real C
parser, not regexes) and emits one exported ``extern "C"`` Rust stub per
public function declaration, preserving the original C symbol names.

Preprocessing
-------------
pycparser cannot consume system headers such as ``<stdint.h>`` and the
installed pycparser wheel does not ship its ``fake_libc_include`` header set,
so this script performs a small, deterministic preprocessing pass instead of
shelling out to ``cpp``:

1. strip ``//`` and ``/* */`` comments (newlines preserved so source line
   numbers survive);
2. evaluate ``#ifdef``/``#ifndef``/``#else``/``#endif`` with an empty macro
   table (this drops the ``extern "C"`` C++ guard block); other conditionals
   (``#if <expr>``) are conservatively taken as true;
3. blank out all remaining preprocessor directives (``#include``,
   ``#define`` including line continuations, ...);
4. prepend a fixed typedef prelude providing the external types the header
   needs (``uint32_t``, ``size_t``, ``TPM_BOOL``, ...), separated from the
   header body by ``#line`` markers so diagnostics and declaration
   coordinates point at the real header file and line.

Any type that is not present in the explicit mapping tables below causes the
script to fail with the offending C type, the affected function, and the
source location. Nothing is silently guessed.

The output is byte-deterministic and is only rewritten when its content
actually changes.
"""

import argparse
import difflib
import os
import re
import sys

try:
    from pycparser import c_ast, c_generator, c_parser
    from pycparser.plyparser import ParseError
except ImportError as exc:  # pragma: no cover
    sys.stderr.write(
        "error: pycparser is required (pip install pycparser): %s\n" % exc
    )
    sys.exit(1)


class AbiError(Exception):
    """Raised when the header contains something this generator cannot map."""


# ---------------------------------------------------------------------------
# Preprocessing
# ---------------------------------------------------------------------------

PRELUDE_FILENAME = "<abi-generator-prelude>"

# Dummy typedefs so pycparser can parse the header without system includes.
# Only parse-ability matters here; the Rust mapping is table-driven below.
PRELUDE = """\
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;
typedef unsigned long size_t;
typedef long ssize_t;
typedef unsigned char TPM_BOOL;
typedef uint32_t TPM_RESULT;
typedef uint32_t TPM_MODIFIER_INDICATOR;
"""

_COMMENT_RE = re.compile(
    r"//[^\n]*|/\*.*?\*/",
    re.DOTALL,
)


def strip_comments(text):
    """Remove C comments, preserving newlines so line numbers stay valid."""

    def repl(match):
        return "\n" * match.group(0).count("\n")

    return _COMMENT_RE.sub(repl, text)


def _strip_conditionals(lines):
    """Blank out directives and inactive #ifdef/#ifndef regions.

    Works with an empty macro table: ``#ifdef X`` is always false and
    ``#ifndef X`` always true, which is exactly right for include guards and
    the ``#ifdef __cplusplus`` / ``extern "C"`` wrapper. A general ``#if``
    expression is conservatively treated as true.
    """
    out = []
    stack = []  # activity of each open conditional
    continuation = False
    for line in lines:
        stripped = line.strip()
        if continuation:
            out.append("")
            continuation = stripped.endswith("\\")
            continue
        if stripped.startswith("#"):
            out.append("")
            continuation = stripped.endswith("\\")
            directive = stripped[1:].strip()
            keyword = directive.split(None, 1)[0] if directive else ""
            active = all(stack)
            if keyword == "ifdef":
                stack.append(False)
            elif keyword == "ifndef":
                stack.append(True)
            elif keyword == "if":
                stack.append(True)
            elif keyword == "elif":
                if stack:
                    stack[-1] = False
            elif keyword == "else":
                if stack:
                    stack[-1] = not stack[-1]
            elif keyword == "endif":
                if stack:
                    stack.pop()
            elif keyword == "error" and active:
                raise AbiError("header hit #error directive: %s" % directive)
            continue
        out.append(line if all(stack) else "")
    return out


def preprocess(text, header_path):
    """Turn raw header text into pycparser-parseable C."""
    text = strip_comments(text)
    body = "\n".join(_strip_conditionals(text.split("\n")))
    return (
        '#line 1 "%s"\n' % PRELUDE_FILENAME
        + PRELUDE
        + '#line 1 "%s"\n' % header_path
        + body
    )


def parse_header(header_path):
    """Parse the header and return (ast, realpath-of-header)."""
    real = os.path.realpath(header_path)
    with open(header_path, "r", encoding="utf-8") as fh:
        text = fh.read()
    processed = preprocess(text, real)
    ast = c_parser.CParser().parse(processed, filename=real)
    return ast, real


# ---------------------------------------------------------------------------
# C -> Rust type mapping
# ---------------------------------------------------------------------------

# Builtin C types (IdentifierType names joined by spaces).
PRIMITIVE_MAP = {
    "char": "core::ffi::c_char",
    "signed char": "core::ffi::c_schar",
    "unsigned char": "core::ffi::c_uchar",
    "short": "core::ffi::c_short",
    "short int": "core::ffi::c_short",
    "unsigned short": "core::ffi::c_ushort",
    "unsigned short int": "core::ffi::c_ushort",
    "int": "core::ffi::c_int",
    "signed int": "core::ffi::c_int",
    "unsigned": "core::ffi::c_uint",
    "unsigned int": "core::ffi::c_uint",
    "long": "core::ffi::c_long",
    "long int": "core::ffi::c_long",
    "unsigned long": "core::ffi::c_ulong",
    "unsigned long int": "core::ffi::c_ulong",
    "int8_t": "i8",
    "uint8_t": "u8",
    "int16_t": "i16",
    "uint16_t": "u16",
    "int32_t": "i32",
    "uint32_t": "u32",
    "int64_t": "i64",
    "uint64_t": "u64",
    "size_t": "usize",
    "ssize_t": "isize",
}

# libtpms typedefs, mapped to Rust-style aliases handwritten in
# src/ffi_types.rs.
TYPEDEF_MAP = {
    "TPM_RESULT": "TpmResult",
    "TPM_BOOL": "TpmBool",
    "TPM_MODIFIER_INDICATOR": "TpmModifierIndicator",
    "TPMLIB_TPMVersion": "TpmlibTpmVersion",
}

# Known enum tags (C enums have the ABI of int; src/ffi_types.rs defines
# c_int aliases under the mapped Rust names).
ENUM_TAG_MAP = {
    "TPMLIB_TPMProperty": "TpmlibTpmProperty",
    "TPMLIB_InfoFlags": "TpmlibInfoFlags",
    "TPMLIB_BlobType": "TpmlibBlobType",
    "TPMLIB_StateType": "TpmlibStateType",
}

# Known struct tags mirrored by handwritten #[repr(C)] Rust structures. Public
# API functions currently use them only behind pointers.
OPAQUE_STRUCT_MAP = {
    "libtpms_callbacks": "LibtpmsCallbacks",
}

# Rust keywords that need escaping when used as parameter names.
RUST_KEYWORDS = {
    "as", "async", "await", "become", "box", "break", "const", "continue",
    "do", "dyn", "else", "enum", "extern", "false", "final", "fn", "for",
    "gen", "if", "impl", "in", "let", "loop", "macro", "match", "mod",
    "move", "mut", "override", "priv", "pub", "ref", "return", "static",
    "struct", "trait", "true", "try", "type", "typeof", "unsafe", "unsized",
    "use", "virtual", "where", "while", "yield",
}
# Keywords that cannot be raw identifiers (r#...): add a trailing underscore.
RUST_NON_RAWABLE = {"self", "Self", "super", "crate"}

_c_generator = c_generator.CGenerator()


def _render_c_type(node):
    """Render an AST type node back to C source for error messages.

    The declarator name is temporarily removed so the result is the bare
    type (``double``), not the declaration (``double Bad``).
    """
    try:
        inner = node
        while isinstance(inner, (c_ast.PtrDecl, c_ast.ArrayDecl,
                                 c_ast.FuncDecl)):
            inner = inner.type
        saved = None
        if isinstance(inner, c_ast.TypeDecl):
            saved = inner.declname
            inner.declname = None
        try:
            wrapper = c_ast.Typename(name=None, quals=[], align=None,
                                     type=node)
            return _c_generator.visit(wrapper).strip()
        finally:
            if isinstance(inner, c_ast.TypeDecl):
                inner.declname = saved
    except Exception:  # pragma: no cover - best effort for diagnostics
        return type(node).__name__


def _fail(func_name, node, message):
    coord = getattr(node, "coord", None)
    raise AbiError(
        "function '%s' (declared at %s) uses unsupported C type '%s': %s. "
        "If this type should be part of the ABI, add it to the mapping "
        "tables in scripts/generate_libtpms_abi.py and, for named types, "
        "declare its Rust counterpart in src/ffi_types.rs."
        % (func_name, coord or "<unknown location>", _render_c_type(node),
           message)
    )


def _is_void(node):
    return (
        isinstance(node, c_ast.TypeDecl)
        and isinstance(node.type, c_ast.IdentifierType)
        and node.type.names == ["void"]
    )


def map_c_type(node, func_name, behind_pointer=False):
    """Map a pycparser type node to a Rust FFI type string."""
    if isinstance(node, c_ast.PtrDecl):
        pointee = node.type
        if _is_void(pointee):
            inner = "core::ffi::c_void"
        else:
            inner = map_c_type(pointee, func_name, behind_pointer=True)
        const = "const" in getattr(pointee, "quals", [])
        return ("*const %s" if const else "*mut %s") % inner

    if isinstance(node, c_ast.TypeDecl):
        inner = node.type
        if isinstance(inner, c_ast.IdentifierType):
            key = " ".join(inner.names)
            if key == "void":
                _fail(func_name, node, "'void' is only valid as a return "
                      "type or behind a pointer")
            if key in PRIMITIVE_MAP:
                return PRIMITIVE_MAP[key]
            if key in TYPEDEF_MAP:
                return TYPEDEF_MAP[key]
            _fail(func_name, node, "no Rust mapping for this C type")
        if isinstance(inner, c_ast.Enum):
            if inner.name in ENUM_TAG_MAP:
                return ENUM_TAG_MAP[inner.name]
            _fail(func_name, node, "unknown enum tag" if inner.name
                  else "anonymous enum")
        if isinstance(inner, c_ast.Struct):
            if inner.name in OPAQUE_STRUCT_MAP:
                if behind_pointer:
                    return OPAQUE_STRUCT_MAP[inner.name]
                _fail(func_name, node, "opaque struct passed by value; only "
                      "pointers to it are supported")
            _fail(func_name, node, "unknown struct tag")
        if isinstance(inner, c_ast.Union):
            _fail(func_name, node, "unions are not supported")
        _fail(func_name, node, "unrecognized type declaration")

    if isinstance(node, c_ast.ArrayDecl):
        _fail(func_name, node, "array parameters are not supported")
    if isinstance(node, c_ast.FuncDecl):
        _fail(func_name, node, "bare function types are not supported")
    _fail(func_name, node, "unrecognized AST node %s" % type(node).__name__)


# Splits a CamelCase/acronym segment: "ChooseTPMVersion" -> Choose, TPM,
# Version; "SetDebugFD" -> Set, Debug, FD.
_NAME_TOKEN_RE = re.compile(
    r"[A-Z]+(?=[A-Z][a-z0-9])|[A-Z][a-z0-9]+|[A-Z]+|[0-9]+|[a-z0-9]+"
)


def rust_impl_name(c_name):
    """Derive the snake_case name of the crate::ffi_api adapter.

    ``TPMLIB_ChooseTPMVersion`` -> ``choose_tpm_version``,
    ``TPMLIB_VolatileAll_Store`` -> ``volatile_all_store``.
    """
    base = c_name
    if base.startswith("TPMLIB_"):
        base = base[len("TPMLIB_"):]
    tokens = []
    for part in base.split("_"):
        if not part:
            continue
        found = _NAME_TOKEN_RE.findall(part)
        if "".join(found) != part:
            raise AbiError(
                "cannot derive a Rust implementation name for '%s': "
                "unsupported characters in segment '%s'" % (c_name, part)
            )
        tokens.extend(found)
    if not tokens:
        raise AbiError(
            "cannot derive a Rust implementation name for '%s'" % c_name
        )
    return "_".join(token.lower() for token in tokens)


def _rust_param_name(name, index):
    if not name:
        return "arg%d" % index
    if name in RUST_NON_RAWABLE:
        return name + "_"
    if name in RUST_KEYWORDS:
        return "r#" + name
    return name


# ---------------------------------------------------------------------------
# Function collection
# ---------------------------------------------------------------------------

class AbiFunction(object):
    def __init__(self, name, params, ret, coord):
        self.name = name          # C symbol name
        self.params = params      # list of (rust_name, rust_type)
        self.ret = ret            # Rust type string, or None for void
        self.coord = coord


def _collect_params(func_decl, func_name):
    args = func_decl.args
    if args is None:
        return []
    params = list(args.params)
    # `f(void)` -> no parameters
    if len(params) == 1 and isinstance(params[0], (c_ast.Typename, c_ast.Decl)) \
            and params[0].name is None and _is_void(params[0].type):
        return []
    out = []
    for index, param in enumerate(params):
        if isinstance(param, c_ast.EllipsisParam):
            raise AbiError(
                "unsupported declaration for function '%s': variadic "
                "functions are not supported at %s"
                % (func_name, param.coord or func_decl.coord)
            )
        name = _rust_param_name(getattr(param, "name", None), index)
        rust_type = map_c_type(param.type, func_name)
        out.append((name, rust_type))
    return out


def collect_functions(ast, header_realpath):
    """Extract public function declarations located in the header itself."""
    functions = []
    for node in ast.ext:
        if not isinstance(node, c_ast.Decl):
            continue  # Typedef, enum/struct definitions, ...
        if not isinstance(node.type, c_ast.FuncDecl):
            continue  # variable declarations, bare struct/enum decls
        if node.coord is None or \
                os.path.realpath(node.coord.file) != header_realpath:
            continue  # prelude content
        if "static" in (node.storage or []):
            continue  # not part of the public ABI
        name = node.name
        func_decl = node.type
        ret = None
        if not _is_void(func_decl.type):
            ret = map_c_type(func_decl.type, name)
        params = _collect_params(func_decl, name)
        functions.append(AbiFunction(name, params, ret, node.coord))
    return functions


# ---------------------------------------------------------------------------
# FFI type cross-check
# ---------------------------------------------------------------------------

class _TypeNameCollector(c_ast.NodeVisitor):
    """Collects non-primitive C type names referenced or defined in a subtree."""

    def __init__(self):
        self.names = set()

    def visit_IdentifierType(self, node):
        key = " ".join(node.names)
        if key != "void" and key not in PRIMITIVE_MAP:
            self.names.add(key)

    def visit_Enum(self, node):
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_Struct(self, node):
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_Union(self, node):
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_Typedef(self, node):
        self.names.add(node.name)
        self.generic_visit(node)


def collect_header_types(ast, header_realpath):
    """All C type names the header defines or uses, minus C primitives.

    Covers typedefs, enum/struct/union tags, and type names referenced
    anywhere in the header's declarations (function signatures, struct
    members, ...). This is the set of names the handwritten FFI type
    module must mirror.
    """
    collector = _TypeNameCollector()
    for node in ast.ext:
        if node.coord is None or \
                os.path.realpath(node.coord.file) != header_realpath:
            continue
        collector.visit(node)
    return collector.names


_RUST_TYPE_DECL_RE = re.compile(r"^pub (?:type|struct|enum) (\w+)",
                                re.MULTILINE)


def collect_ffi_rust_types(ffi_path):
    """Type names declared in the handwritten Rust FFI module."""
    with open(ffi_path, "r", encoding="utf-8") as fh:
        return set(_RUST_TYPE_DECL_RE.findall(fh.read()))


def check_ffi_types(header_types, ffi_path):
    """Bidirectional check between header C types and the FFI module.

    Returns a list of error strings (empty when everything matches):
    - every header type must have a mapping-table entry;
    - every mapped Rust name must be declared in the FFI module;
    - every type declared in the FFI module must correspond to a header type.
    """
    errors = []
    expected_rust = set()
    for c_name in sorted(header_types):
        rust_name = (TYPEDEF_MAP.get(c_name)
                     or ENUM_TAG_MAP.get(c_name)
                     or OPAQUE_STRUCT_MAP.get(c_name))
        if rust_name is None:
            errors.append(
                "C type '%s' from the header has no entry in the generator "
                "mapping tables" % c_name
            )
            continue
        expected_rust.add(rust_name)
    declared = collect_ffi_rust_types(ffi_path)
    for rust_name in sorted(expected_rust - declared):
        errors.append(
            "Rust type '%s' (required by the header) is not declared in %s"
            % (rust_name, ffi_path)
        )
    for rust_name in sorted(declared - expected_rust):
        errors.append(
            "Rust type '%s' declared in %s does not correspond to any type "
            "in the header" % (rust_name, ffi_path)
        )
    return errors


# ---------------------------------------------------------------------------
# FFI struct layout cross-check
# ---------------------------------------------------------------------------

class AbiStruct(object):
    def __init__(self, c_name, rust_name, fields, coord):
        self.c_name = c_name
        self.rust_name = rust_name
        self.fields = fields
        self.coord = coord


def _map_callback_type(node, struct_name, field_name):
    """Map a C function pointer field to Option<unsafe extern "C" fn(...)>."""
    if not isinstance(node, c_ast.PtrDecl) or \
            not isinstance(node.type, c_ast.FuncDecl):
        return map_c_type(node, "%s.%s" % (struct_name, field_name))

    func = node.type
    params = []
    if func.args is not None:
        raw_params = list(func.args.params)
        if not (len(raw_params) == 1 and
                isinstance(raw_params[0], (c_ast.Typename, c_ast.Decl)) and
                raw_params[0].name is None and _is_void(raw_params[0].type)):
            for param in raw_params:
                if isinstance(param, c_ast.EllipsisParam):
                    raise AbiError(
                        "struct '%s' field '%s' is variadic; variadic callback "
                        "types are unsupported" % (struct_name, field_name)
                    )
                params.append(map_c_type(
                    param.type, "%s.%s" % (struct_name, field_name)
                ))
    ret = None if _is_void(func.type) else map_c_type(
        func.type, "%s.%s" % (struct_name, field_name)
    )
    signature = "unsafe extern \"C\" fn(%s)" % ", ".join(params)
    if ret is not None:
        signature += " -> %s" % ret
    return "Option<%s>" % signature


def collect_header_structs(ast, header_realpath):
    """Collect mapped, defined public C structs and their ordered fields."""
    structs = []
    seen = set()

    class Visitor(c_ast.NodeVisitor):
        def visit_Struct(self, node):
            if node.name in OPAQUE_STRUCT_MAP and node.decls is not None and \
                    node.name not in seen and node.coord is not None and \
                    os.path.realpath(node.coord.file) == header_realpath:
                fields = []
                for field in node.decls:
                    rust_field = rust_impl_name(field.name)
                    rust_type = _map_callback_type(
                        field.type, node.name, field.name
                    )
                    fields.append((rust_field, rust_type))
                structs.append(AbiStruct(
                    node.name, OPAQUE_STRUCT_MAP[node.name], fields, node.coord
                ))
                seen.add(node.name)
            self.generic_visit(node)

    Visitor().visit(ast)
    return structs


def _find_matching_delimiter(text, start, opening, closing):
    """Find a closing Rust delimiter while ignoring strings and comments."""
    depth = 0
    index = start
    state = "code"
    block_depth = 0
    while index < len(text):
        ch = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if state == "line_comment":
            if ch == "\n":
                state = "code"
        elif state == "block_comment":
            if ch == "/" and nxt == "*":
                block_depth += 1
                index += 1
            elif ch == "*" and nxt == "/":
                block_depth -= 1
                index += 1
                if block_depth == 0:
                    state = "code"
        elif state == "string":
            if ch == "\\":
                index += 1
            elif ch == '"':
                state = "code"
        else:
            if ch == "/" and nxt == "/":
                state = "line_comment"
                index += 1
            elif ch == "/" and nxt == "*":
                state = "block_comment"
                block_depth = 1
                index += 1
            elif ch == '"':
                state = "string"
            elif ch == opening:
                depth += 1
            elif ch == closing:
                depth -= 1
                if depth == 0:
                    return index
        index += 1
    raise AbiError("unterminated '%s' delimiter in Rust FFI module" % opening)


def _strip_rust_comments(text):
    text = re.sub(r"//[^\n]*", "", text)
    return re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)


def _split_rust_fields(body):
    """Split a Rust named-field body on top-level commas."""
    fields = []
    start = 0
    depths = {"(": 0, "[": 0, "{": 0, "<": 0}
    closing = {")": "(", "]": "[", "}": "{", ">": "<"}
    in_string = False
    escaped = False
    for index, ch in enumerate(body):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in depths:
            depths[ch] += 1
        elif ch == ">" and index > 0 and body[index - 1] == "-":
            # Return-type arrow, not a generic closing delimiter.
            continue
        elif ch in closing:
            key = closing[ch]
            depths[key] = max(0, depths[key] - 1)
        elif ch == "," and not any(depths.values()):
            fields.append(body[start:index])
            start = index + 1
    if body[start:].strip():
        fields.append(body[start:])
    return fields


def _normalize_rust_type(rust_type):
    rust_type = re.sub(r"\s+", " ", rust_type.strip())
    rust_type = re.sub(r"\s*([<>,();\[\]])\s*", r"\1", rust_type)
    # rustfmt permits trailing commas in multiline generic and function
    # argument lists; they do not change the type.
    rust_type = re.sub(r",([)>])", r"\1", rust_type)
    return rust_type


_RUST_TYPE_ALIAS_RE = re.compile(r"\bpub\s+type\s+(\w+)\s*=\s*([^;]+);")

# Path prefixes under which the last segment names a C primitive; spelling
# a type with or without them (e.g. via `use core::ffi::c_int`) does not
# change the ABI.
_RUST_PRIMITIVE_PATH_RE = re.compile(r"\b(?:core|std)::(?:ffi|os::raw)::(\w+)")


def collect_rust_type_aliases(ffi_path):
    """Map `pub type Name = Rhs;` aliases of the Rust FFI module."""
    with open(ffi_path, "r", encoding="utf-8") as fh:
        source = _strip_rust_comments(fh.read())
    return {
        name: _normalize_rust_type(rhs)
        for name, rhs in _RUST_TYPE_ALIAS_RE.findall(source)
    }


def _canonicalize_rust_type(rust_type, aliases):
    """Reduce a Rust type to its ABI-canonical spelling.

    Strips primitive path prefixes and resolves ``pub type`` aliases
    transitively, so ABI-equivalent spellings such as
    ``*mut TpmModifierIndicator``, ``*mut core::ffi::c_uint`` and
    ``*mut u32`` all compare equal.
    """
    current = _normalize_rust_type(rust_type)
    for _ in range(16):
        previous = current
        current = _RUST_PRIMITIVE_PATH_RE.sub(r"\1", current)
        current = re.sub(
            r"\b\w+\b",
            lambda m: aliases.get(m.group(0), m.group(0)),
            current,
        )
        if current == previous:
            return current
    raise AbiError(
        "type alias resolution did not converge for '%s' (alias cycle?)"
        % rust_type
    )


def collect_rust_structs(ffi_path):
    """Structurally parse named fields of public Rust FFI structs."""
    with open(ffi_path, "r", encoding="utf-8") as fh:
        source = fh.read()
    structs = {}
    pattern = re.compile(r"\bpub\s+struct\s+(\w+)\s*\{")
    for match in pattern.finditer(source):
        name = match.group(1)
        opening = source.find("{", match.start())
        closing = _find_matching_delimiter(source, opening, "{", "}")
        before = source[:match.start()]
        declaration_start = max(before.rfind("}"), before.rfind(";")) + 1
        attributes = before[declaration_start:]
        repr_c = bool(re.search(
            r"#\s*\[\s*repr\s*\(\s*C\s*\)\s*\]", attributes
        ))
        body = _strip_rust_comments(source[opening + 1:closing])
        fields = []
        for raw_field in _split_rust_fields(body):
            raw_field = re.sub(r"#\s*\[[^]]*\]", "", raw_field).strip()
            if not raw_field:
                continue
            field_match = re.match(
                r"(?:(?:pub)(?:\s*\([^)]*\))?\s+)?(\w+)\s*:\s*(.*)\Z",
                raw_field, re.DOTALL
            )
            if field_match is None:
                raise AbiError(
                    "cannot parse field in Rust struct '%s': %s" %
                    (name, raw_field.strip())
                )
            fields.append((field_match.group(1),
                           _normalize_rust_type(field_match.group(2))))
        structs[name] = (repr_c, fields)
    return structs


def _render_layout(name, fields, repr_c=True):
    lines = ["#[repr(C)]" if repr_c else "#[missing repr(C)]",
             "pub struct %s {" % name]
    lines.extend("    %s: %s," % (field_name,
                                  _normalize_rust_type(field_type))
                 for field_name, field_type in fields)
    lines.append("}")
    return lines


def check_ffi_structs(header_structs, ffi_path):
    """Return unified layout diffs for mapped C/Rust structures.

    Field types on both sides are canonicalized (primitive path prefixes
    stripped, ``pub type`` aliases resolved) before comparison, so only
    genuine ABI differences are reported; the diff shows the canonical
    spellings.
    """
    errors = []
    rust_structs = collect_rust_structs(ffi_path)
    aliases = collect_rust_type_aliases(ffi_path)

    def canonical(fields):
        return [(name, _canonicalize_rust_type(rust_type, aliases))
                for name, rust_type in fields]

    for c_struct in header_structs:
        actual = rust_structs.get(c_struct.rust_name)
        if actual is None:
            errors.append(
                "Rust struct '%s' for C struct '%s' is missing from %s" %
                (c_struct.rust_name, c_struct.c_name, ffi_path)
            )
            continue
        repr_c, actual_fields = actual
        expected_lines = _render_layout(c_struct.rust_name,
                                        canonical(c_struct.fields))
        actual_lines = _render_layout(c_struct.rust_name,
                                      canonical(actual_fields), repr_c)
        if expected_lines != actual_lines:
            diff = "\n".join(difflib.unified_diff(
                expected_lines, actual_lines,
                fromfile="C struct %s (expected Rust ABI, canonicalized)"
                         % c_struct.c_name,
                tofile="%s struct %s (canonicalized)"
                       % (ffi_path, c_struct.rust_name),
                lineterm=""
            ))
            errors.append("FFI struct layout mismatch:\n%s" % diff)
    return errors


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

# rustfmt's default max_width; signatures longer than this are wrapped to
# one parameter per line, mirroring rustfmt so the generated file passes
# `cargo fmt --check` byte-for-byte.
RUST_MAX_WIDTH = 100


def _render_signature(func):
    """Render the `pub unsafe extern "C" fn ...(...) ... {` line(s)."""
    params = ", ".join("%s: %s" % (n, t) for n, t in func.params)
    ret = " -> %s" % func.ret if func.ret is not None else ""
    single = 'pub unsafe extern "C" fn %s(%s)%s {' % (func.name, params, ret)
    if len(single) <= RUST_MAX_WIDTH:
        return [single]
    lines = ['pub unsafe extern "C" fn %s(' % func.name]
    for name, rust_type in func.params:
        lines.append("    %s: %s," % (name, rust_type))
    lines.append(")%s {" % ret)
    return lines


def _render_body(func):
    """Render the delegating wrapper body, wrapped like rustfmt would."""
    impl_name = rust_impl_name(func.name)
    if not func.params:
        # `ffi_guard(f)` instead of `ffi_guard(|| f())`: no redundant closure.
        return ["    ffi_guard(crate::ffi_api::%s)" % impl_name]
    args = ", ".join(name for name, _ in func.params)
    call = "crate::ffi_api::%s(%s)" % (impl_name, args)
    has_raw_pointer = any(rust_type.startswith("*") for _, rust_type in func.params)
    if has_raw_pointer:
        single = "    ffi_guard(|| unsafe { %s })" % call
        if len(single) <= RUST_MAX_WIDTH:
            return [single]
        inner = "        %s" % call
        if len(inner) <= RUST_MAX_WIDTH:
            return ["    ffi_guard(|| unsafe {", inner, "    })"]
        lines = ["    ffi_guard(|| unsafe {", "        crate::ffi_api::%s(" % impl_name]
        for name, _ in func.params:
            lines.append("            %s," % name)
        lines += ["        )", "    })"]
        return lines
    single = "    ffi_guard(|| %s)" % call
    if len(single) <= RUST_MAX_WIDTH:
        return [single]
    inner = "        %s" % call
    if len(inner) <= RUST_MAX_WIDTH:
        return ["    ffi_guard(|| {", inner, "    })"]
    lines = ["    ffi_guard(|| {", "        crate::ffi_api::%s(" % impl_name]
    for name, _ in func.params:
        lines.append("            %s," % name)
    lines += ["        )", "    })"]
    return lines


def render_rust(functions, header_display):
    impl_names = {}
    for func in functions:
        impl_name = rust_impl_name(func.name)
        if impl_name in impl_names:
            raise AbiError(
                "functions '%s' and '%s' both map to Rust implementation "
                "name '%s'" % (impl_names[impl_name], func.name, impl_name)
            )
        impl_names[impl_name] = func.name
    lines = [
        "// This file is automatically generated. Do not edit it manually.",
        "// Source: %s" % header_display,
        "// Regenerate with: make generate-abi",
        "",
        "#![allow(non_snake_case)]",
        "#![allow(unused_imports)]",
        "// Thin delegating wrappers only; the C-to-Rust adaptation lives in",
        "// src/ffi_api.rs. The wrappers carry no per-function safety docs; the",
        "// safety contract is the libtpms C API documented in tpm_library.h.",
        "#![allow(clippy::missing_safety_doc)]",
        "",
        "use crate::ffi_support::ffi_guard;",
        "use crate::ffi_types::*;",
    ]
    for func in functions:
        lines += ["", "#[unsafe(no_mangle)]"]
        lines += _render_signature(func)
        lines += _render_body(func)
        lines += ["}"]
    return "\n".join(lines) + "\n"


def render_manifest(functions):
    return "\n".join(sorted(func.name for func in functions)) + "\n"


def write_if_changed(path, content):
    """Write ``content`` to ``path`` only if it differs; return True if written."""
    data = content.encode("utf-8")
    try:
        with open(path, "rb") as fh:
            if fh.read() == data:
                return False
    except FileNotFoundError:
        pass
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate Rust C-ABI stubs from the libtpms public header."
    )
    parser.add_argument("--header", required=True,
                        help="path to tpm_library.h")
    parser.add_argument("--output", default=None,
                        help="path of the generated Rust source file")
    parser.add_argument("--manifest", default=None,
                        help="optional path for a sorted list of ABI "
                             "function names, one per line")
    parser.add_argument("--check-ffi-types", default=None, metavar="FFI_RS",
                        help="cross-check the header's type names against "
                             "the handwritten Rust FFI type module "
                             "(e.g. src/ffi_types.rs); no files are written")
    args = parser.parse_args(argv)

    if not args.output and not args.check_ffi_types:
        parser.error("at least one of --output or --check-ffi-types "
                     "is required")

    if not os.path.isfile(args.header):
        sys.stderr.write("error: header not found: %s\n" % args.header)
        return 1
    if args.check_ffi_types and not os.path.isfile(args.check_ffi_types):
        sys.stderr.write("error: FFI type module not found: %s\n"
                         % args.check_ffi_types)
        return 1

    try:
        ast, real = parse_header(args.header)
    except (AbiError, ParseError) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 1

    if args.output:
        try:
            functions = collect_functions(ast, real)
        except (AbiError, ParseError) as exc:
            sys.stderr.write("error: %s\n" % exc)
            return 1
        if not functions:
            sys.stderr.write(
                "error: no public function declarations found in %s\n"
                % args.header
            )
            return 1
        header_display = args.header.replace(os.sep, "/")
        changed = write_if_changed(args.output, render_rust(functions,
                                                            header_display))
        print("%s: %s (%d functions)"
              % (args.output, "updated" if changed else "unchanged",
                 len(functions)))
        if args.manifest:
            m_changed = write_if_changed(args.manifest,
                                         render_manifest(functions))
            print("%s: %s" % (args.manifest,
                              "updated" if m_changed else "unchanged"))

    if args.check_ffi_types:
        header_types = collect_header_types(ast, real)
        errors = check_ffi_types(header_types, args.check_ffi_types)
        header_structs = collect_header_structs(ast, real)
        errors.extend(check_ffi_structs(header_structs,
                                        args.check_ffi_types))
        if errors:
            for error in errors:
                sys.stderr.write("error: %s\n" % error)
            return 1
        print("check-ffi-types: OK (%d C types, %d struct layouts <-> %s)"
              % (len(header_types), len(header_structs),
                 args.check_ffi_types))
    return 0


if __name__ == "__main__":
    sys.exit(main())
