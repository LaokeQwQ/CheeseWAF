import importlib.util
import io
import pathlib
import stat
import tarfile
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("acceptance_matrix_v2", ROOT / "scripts/acceptance/matrix.py")
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)
scanner_spec = importlib.util.spec_from_file_location("artifact_scan", ROOT / "scripts/acceptance/production_artifact_scan.py")
scanner = importlib.util.module_from_spec(scanner_spec)
scanner_spec.loader.exec_module(scanner)


class AcceptanceMatrixV2Tests(unittest.TestCase):
    def test_catalog_has_required_gates_without_duplicates(self):
        ids = [gate[0] for gate in matrix.GATES] + ["cleanup_no_tracked_pollution"]
        self.assertEqual(len(ids), len(set(ids)))
        required = {
            "control_health_ready_status", "control_postgres_dsn",
            "native_raft_single_node_restart", "native_raft_join_only",
            "production_serve_fail_closed", "crp_stage", "crp_activation",
            "crp_rollback", "approval_http", "token_strict_identity",
            "diagnostics_encryption", "diagnostics_queue", "diagnostics_runtime_delivery",
            "offline_no_egress", "temporary_network_confirmation", "production_artifact_scan",
        }
        self.assertTrue(required.issubset(ids))

    def test_sanitizer_redacts_dsn_password_and_token(self):
        text = "postgres://control:super-secret@db.example/control password=abc token=xyz"
        safe = matrix.sanitize(text)
        self.assertNotIn("super-secret", safe)
        self.assertNotIn("abc", safe)
        self.assertNotIn("xyz", safe)
        self.assertIn("[REDACTED]", safe)

    def test_report_path_inside_repository_is_rejected(self):
        with self.assertRaises(SystemExit):
            matrix.main(["--static", "--report", str(ROOT / "acceptance-report.json")])

    def test_artifact_scanner_rejects_dependency_tree_in_zip_member(self):
        with tempfile.TemporaryDirectory(prefix="cheesewaf-artifact-test-") as directory:
            root = pathlib.Path(directory)
            (root / "web/dist").mkdir(parents=True)
            (root / "internal/webui/dist").mkdir(parents=True)
            (root / "release").mkdir()
            (root / "scripts/ci").mkdir(parents=True)
            (root / "scripts/ci/build-web.sh").write_text("npm ci --no-audit --no-fund --ignore-scripts\\n", encoding="utf-8")
            with zipfile.ZipFile(root / "web/dist" / "bundle.zip", "w") as archive:
                archive.writestr("node_modules/dev-only/index.js", "development dependency")
            with self.assertRaises(SystemExit):
                scanner.scan(root)

    def test_artifact_scanner_rejects_source_tree_at_dist_root(self):
        with tempfile.TemporaryDirectory(prefix="cheesewaf-artifact-test-") as directory:
            root = pathlib.Path(directory)
            (root / "web/dist/src").mkdir(parents=True)
            (root / "web/dist/src/leak.js").write_text("source leak", encoding="utf-8")
            (root / "internal/webui/dist").mkdir(parents=True)
            (root / "release").mkdir()
            (root / "scripts/ci").mkdir(parents=True)
            (root / "scripts/ci/build-web.sh").write_text("npm ci --no-audit --no-fund --ignore-scripts\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                scanner.scan(root)

    def test_artifact_scanner_rejects_unsafe_zip_paths(self):
        for member_name in ("C:/Windows/System32/escape", "C:drive-relative", "/absolute/escape", "../escape"):
            with self.subTest(member_name=member_name):
                with tempfile.TemporaryDirectory(prefix="cheesewaf-artifact-test-") as directory:
                    root = pathlib.Path(directory)
                    (root / "web/dist").mkdir(parents=True)
                    (root / "internal/webui/dist").mkdir(parents=True)
                    (root / "release").mkdir()
                    (root / "scripts/ci").mkdir(parents=True)
                    (root / "scripts/ci/build-web.sh").write_text("npm ci --no-audit --no-fund --ignore-scripts\n", encoding="utf-8")
                    with zipfile.ZipFile(root / "web/dist" / "bundle.zip", "w") as archive:
                        archive.writestr(member_name, "unsafe path")
                    with self.assertRaises(SystemExit):
                        scanner.scan(root)

    def test_artifact_scanner_rejects_nested_archive(self):
        with tempfile.TemporaryDirectory(prefix="cheesewaf-artifact-test-") as directory:
            root = pathlib.Path(directory)
            (root / "web/dist").mkdir(parents=True)
            (root / "internal/webui/dist").mkdir(parents=True)
            (root / "release").mkdir()
            (root / "scripts/ci").mkdir(parents=True)
            (root / "scripts/ci/build-web.sh").write_text("npm ci --no-audit --no-fund --ignore-scripts\n", encoding="utf-8")
            nested = io.BytesIO()
            with zipfile.ZipFile(nested, "w") as archive:
                archive.writestr("node_modules/dev-only/index.js", "development dependency")
            with zipfile.ZipFile(root / "release" / "outer.zip", "w") as archive:
                archive.writestr("nested.zip", nested.getvalue())
            with self.assertRaises(SystemExit):
                scanner.scan(root)

    def test_artifact_scanner_rejects_tar_special_member(self):
        with tempfile.TemporaryDirectory(prefix="cheesewaf-artifact-test-") as directory:
            root = pathlib.Path(directory)
            (root / "web/dist").mkdir(parents=True)
            (root / "internal/webui/dist").mkdir(parents=True)
            (root / "release").mkdir()
            (root / "scripts/ci").mkdir(parents=True)
            (root / "scripts/ci/build-web.sh").write_text("npm ci --no-audit --no-fund --ignore-scripts\n", encoding="utf-8")
            with tarfile.open(root / "release" / "bundle.tar.gz", "w:gz") as archive:
                member = tarfile.TarInfo("device")
                member.type = tarfile.CHRTYPE
                archive.addfile(member)
            with self.assertRaises(SystemExit):
                scanner.scan(root)

    def test_artifact_scanner_inspects_top_level_tgz(self):
        with tempfile.TemporaryDirectory(prefix="cheesewaf-artifact-test-") as directory:
            root = pathlib.Path(directory)
            (root / "web/dist").mkdir(parents=True)
            (root / "internal/webui/dist").mkdir(parents=True)
            (root / "release").mkdir()
            (root / "scripts/ci").mkdir(parents=True)
            (root / "scripts/ci/build-web.sh").write_text("npm ci --no-audit --no-fund --ignore-scripts\n", encoding="utf-8")
            payload = b"development dependency"
            with tarfile.open(root / "release" / "bundle.tgz", "w:gz") as archive:
                member = tarfile.TarInfo("node_modules/dev-only/index.js")
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
            with self.assertRaises(SystemExit):
                scanner.scan(root)

    def test_artifact_scanner_rejects_zip_special_member(self):
        with tempfile.TemporaryDirectory(prefix="cheesewaf-artifact-test-") as directory:
            root = pathlib.Path(directory)
            (root / "web/dist").mkdir(parents=True)
            (root / "internal/webui/dist").mkdir(parents=True)
            (root / "release").mkdir()
            (root / "scripts/ci").mkdir(parents=True)
            (root / "scripts/ci/build-web.sh").write_text("npm ci --no-audit --no-fund --ignore-scripts\n", encoding="utf-8")
            member = zipfile.ZipInfo("device")
            member.create_system = 3
            member.external_attr = (stat.S_IFCHR | 0o600) << 16
            with zipfile.ZipFile(root / "release" / "bundle.ZIP", "w") as archive:
                archive.writestr(member, b"")
            with self.assertRaises(SystemExit):
                scanner.scan(root)


if __name__ == "__main__":
    unittest.main()
