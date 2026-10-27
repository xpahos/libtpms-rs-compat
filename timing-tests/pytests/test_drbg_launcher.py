import hashlib
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("drbg_launcher", ROOT / "timing-tests" / "run.py")
launcher_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher_module)
spec = importlib.util.spec_from_file_location("drbg_reference", ROOT / "timing-tests" / "drbg_reference.py")
reference_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference_module)


class InstrumentedBuilds(unittest.TestCase):
    def test_rust_hooks_use_separate_target_and_record_enabled_features(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ordinary = root / "target" / "release" / "libtpms.so"
            ordinary.parent.mkdir(parents=True)
            ordinary.write_bytes(b"ordinary library")
            stage = SimpleNamespace(record={})
            commands = []

            def build(_stage, argv, env_extra):
                commands.append((argv, env_extra))
                output = Path(env_extra["CARGO_TARGET_DIR"]) / "release" / "libtpms.so"
                output.parent.mkdir(parents=True)
                output.write_bytes(b"instrumented library")

            launcher = SimpleNamespace(
                repo=root, cache=root / "cache", artifacts=root / "artifacts", fixture=None,
                cargo=["cargo"], summary={"artifacts": {}}, paths={},
                new_stage=lambda *_: stage, begin=lambda *_: None, finish=lambda *_, **__: None,
                run_checked=build,
            )
            with patch.object(launcher_module, "compiler_environment", return_value={}):
                launcher_module.build_stage_rust(launcher)
            argv, env = commands[0]
            self.assertIn("--features", argv)
            self.assertEqual(set(argv[argv.index("--features") + 1].split(",")), {"tpm2", "timing-test-hooks"})
            self.assertNotEqual(Path(env["CARGO_TARGET_DIR"]), root / "target")
            self.assertNotEqual(Path(env["CARGO_TARGET_DIR"]), root / "cache" / "rust-lib-target")
            self.assertEqual(ordinary.read_bytes(), b"ordinary library")
            artifact = launcher.summary["artifacts"]["rust_library"]
            self.assertEqual(Path(artifact["path"]).read_bytes(), b"instrumented library")
            self.assertEqual(artifact["build_configuration"]["features"], ["tpm2", "timing-test-hooks"])
            self.assertEqual(stage.record["build_configuration"], artifact["build_configuration"])

    def test_reference_patch_inputs_invalidate_cache_and_are_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            helper = root / "timing-tests" / "drbg_reference.py"
            hook = root / "timing-tests" / "c" / "drbg_hook.c"
            hook.parent.mkdir(parents=True)
            helper.write_text("patch recipe v1")
            hook.write_text("hook v1")
            launcher = SimpleNamespace(repo=root, fixture=True)
            # Compiler and OpenSSL discovery are unrelated to source cache invalidation.
            compiler = {"form": "direct", "executable": "cc", "arguments": [], "effective": {"realpath": "/usr/bin/cc"}}
            with patch.object(launcher_module, "resolve_cc", return_value=compiler), \
                    patch.object(launcher_module, "compiler_launcher_script", return_value="cc"), \
                    patch.object(launcher_module, "compiler_exec_argv", return_value=["cc"]), \
                    patch.object(launcher_module, "capture", return_value=(1, "unavailable")), \
                    patch.object(launcher_module, "tool_identity", return_value={}):
                before, first = launcher_module.reference_fingerprint(launcher, "commit", {}, {})
                hook.write_text("hook v2")
                _, second = launcher_module.reference_fingerprint(launcher, "commit", {}, {})
                helper.write_text("patch recipe v2")
                _, third = launcher_module.reference_fingerprint(launcher, "commit", {}, {})
            self.assertNotEqual(first, second)
            self.assertNotEqual(second, third)
            self.assertEqual(before["source_features"], ["timing-test-hooks"])
            self.assertEqual(before["timing_test_sources"], {
                "timing-tests/drbg_reference.py": hashlib.sha256(b"patch recipe v1").hexdigest(),
                "timing-tests/c/drbg_hook.c": hashlib.sha256(b"hook v1").hexdigest(),
            })


class ReferencePatch(unittest.TestCase):
    FILES = ("src/tpm2/crypto/openssl/CryptRand.c", "src/libtpms.syms")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.vendor = self.root / "libtpms"
        for relative in self.FILES:
            destination = self.vendor / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / "libtpms" / relative, destination)
        self.before = [(self.vendor / name).read_bytes() for name in self.FILES]
        self.source = self.root / "isolated"
        shutil.copytree(self.vendor, self.source)
        # Exercise safety checks on a disposable vendor copy, never the real checkout.
        patched_file = patch.object(reference_module, "__file__", str(self.root / "timing-tests" / "drbg_reference.py"))
        patched_file.start()
        self.addCleanup(patched_file.stop)

    def prepare(self, source=None):
        reference_module.prepare_reference(source or self.source, ROOT / "timing-tests" / "c" / "drbg_hook.c")

    def test_only_isolated_copy_receives_hook_and_export(self):
        self.prepare()
        for relative, original in zip(self.FILES, self.before):
            self.assertEqual((self.vendor / relative).read_bytes(), original)
            self.assertIn(b"TPMS_TIMING_DRBG_v1", (self.source / relative).read_bytes())
        with self.assertRaisesRegex(ValueError, "already present"):
            self.prepare()

    def test_export_anchor_drift_leaves_both_files_unchanged(self):
        exports = self.source / self.FILES[1]
        exports.write_text(exports.read_text().replace("TPMLIB_SetProfile;", "TPMLIB_Changed;"))
        before = [(self.source / name).read_bytes() for name in self.FILES]
        with self.assertRaisesRegex(ValueError, "export map entry"):
            self.prepare()
        self.assertEqual([(self.source / name).read_bytes() for name in self.FILES], before)

    def test_vendor_root_is_rejected_without_changes(self):
        with self.assertRaisesRegex(ValueError, "isolated source copy"):
            self.prepare(self.vendor)
        self.assertEqual([(self.vendor / name).read_bytes() for name in self.FILES], self.before)

    def test_symlink_to_vendor_is_rejected_without_changes(self):
        linked = self.source / self.FILES[0]
        linked.unlink()
        linked.symlink_to(self.vendor / self.FILES[0])
        with self.assertRaisesRegex(ValueError, "links into vendored source"):
            self.prepare()
        self.assertEqual([(self.vendor / name).read_bytes() for name in self.FILES], self.before)
        self.assertEqual((self.source / self.FILES[1]).read_bytes(), self.before[1])
