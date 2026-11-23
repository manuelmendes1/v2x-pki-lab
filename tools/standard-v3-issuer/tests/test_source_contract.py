from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "main.cpp"
CMAKE = Path(__file__).resolve().parents[1] / "CMakeLists.txt"
BUILD = Path(__file__).resolve().parents[2] / "build-standard-v3-issuer.sh"


class StandardV3IssuerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.cmake = CMAKE.read_text(encoding="utf-8")
        cls.build = BUILD.read_text(encoding="utf-8")

    def test_experimental_pqc_profile_is_rejected_at_compile_time(self):
        self.assertIn("#ifdef VANETZA_WITH_PQC", self.source)
        self.assertIn("#error", self.source)
        self.assertIn("ASN1_PROFILE=standard", self.build)

    def test_openssl_backend_is_selected_explicitly(self):
        self.assertIn('create_backend_or_throw("OpenSSL")', self.source)
        self.assertNotIn('create_backend_or_throw("default")', self.source)

    def test_vehicle_authorities_issue_both_cam_and_denm(self):
        self.assertIn("v3::add_psid_group_permission(\n        group, aid::CA", self.source)
        self.assertIn("group, aid::DEN", self.source)
        self.assertIn("ROOT_ISSUE_AIDS=36,37", self.source)
        self.assertIn("AA_ISSUE_AIDS=36,37", self.source)

    def test_at_has_both_application_permissions(self):
        self.assertIn("certificate.add_app_permission(aid::CA", self.source)
        self.assertIn("certificate.add_app_permission(aid::DEN", self.source)
        self.assertIn("AT_APPLICATION_AIDS=36,37", self.source)

    def test_validity_hierarchy_is_checked_before_execution(self):
        self.assertIn("options.aa_days > options.root_days", self.source)
        self.assertIn("options.ticket_days > options.aa_days", self.source)

    def test_default_is_dry_run_and_execution_is_explicit(self):
        self.assertIn("bool execute = false", self.source)
        self.assertIn('arg == "--execute"', self.source)
        self.assertIn("FILES_WRITTEN=0", self.source)

    def test_existing_issuance_runs_are_never_overwritten(self):
        self.assertIn("refusing to overwrite existing issuance run", self.source)
        self.assertIn("fs::rename(stage, final_path)", self.source)

    def test_private_key_files_are_restricted(self):
        self.assertIn("S_IRUSR | S_IWUSR", self.source)
        self.assertIn("PEM_write_bio_PrivateKey", self.source)
        self.assertIn("unencrypted PKCS#8 PEM", self.source)

    def test_every_generated_signature_is_checked_before_publishing(self):
        self.assertIn("verify_primary_certificate(root, nullptr, backend)", self.source)
        self.assertIn("verify_primary_certificate(aa, &root, backend)", self.source)
        self.assertIn("verify_primary_certificate(at, &aa, backend)", self.source)
        self.assertIn("validate_chain(root, aa, tickets", self.source)

    def test_trust_anchor_and_issuer_chain_are_explicitly_published(self):
        self.assertIn('trust_dir / "trusted-root.cert"', self.source)
        self.assertIn('chain_dir / "aa.cert"', self.source)
        self.assertIn('chain_dir / "root.cert"', self.source)

    def test_runtime_acceptance_is_not_misreported(self):
        self.assertIn("runtime_acceptance=NOT_YET_DEMONSTRATED", self.source)
        self.assertIn("RUNTIME_ACCEPTANCE=NOT_YET_DEMONSTRATED", self.source)

    def test_cmake_links_standard_vanetza_and_openssl(self):
        self.assertIn("find_package(Vanetza CONFIG REQUIRED)", self.cmake)
        self.assertIn("find_package(OpenSSL REQUIRED COMPONENTS Crypto)", self.cmake)
        self.assertIn("Vanetza::security OpenSSL::Crypto", self.cmake)


if __name__ == "__main__":
    unittest.main(verbosity=2)
