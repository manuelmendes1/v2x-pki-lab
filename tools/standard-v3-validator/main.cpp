#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/clock.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/common/position_fix.hpp>
#include <vanetza/common/stored_position_provider.hpp>
#include <vanetza/geonet/units.hpp>

#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/certificate_validator.hpp>
#include <vanetza/security/v3/issuer_memory_lookup.hpp>
#include <vanetza/security/v3/location_checker.hpp>
#include <vanetza/security/v3/revocation_lookup.hpp>
#include <vanetza/security/v3/trust_store.hpp>

#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

namespace v3 = vanetza::security::v3;

using vanetza::ByteBuffer;
using vanetza::Clock;
using vanetza::ItsAid;
using vanetza::ManualRuntime;
using vanetza::PositionFix;
using vanetza::StoredPositionProvider;
using vanetza::security::v3::Certificate;
using vanetza::security::v3::CertificateValidator;
using vanetza::security::v3::DefaultCertificateValidator;
using vanetza::security::v3::DefaultLocationChecker;
using vanetza::security::v3::IssuerMemoryLookup;
using vanetza::security::v3::RevocationMemoryLookup;
using vanetza::security::v3::TrustStore;

namespace
{

ByteBuffer read_binary_file(const std::string& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("cannot open certificate: " + path);
    }

    const std::vector<char> raw {
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>()
    };

    if (raw.empty()) {
        throw std::runtime_error("empty certificate file: " + path);
    }

    ByteBuffer result;
    result.reserve(raw.size());

    for (const char value : raw) {
        result.push_back(static_cast<std::uint8_t>(
            static_cast<unsigned char>(value)));
    }

    return result;
}

Certificate load_certificate(const std::string& path)
{
    Certificate certificate;
    const auto encoded = read_binary_file(path);

    if (!certificate.decode(encoded)) {
        throw std::runtime_error("OER decoding failed: " + path);
    }

    std::string error;
    if (!certificate.validate(error)) {
        throw std::runtime_error(
            "ASN.1 validation failed for " + path + ": " + error);
    }

    return certificate;
}

const char* verdict_name(CertificateValidator::Verdict verdict)
{
    switch (verdict) {
        case CertificateValidator::Verdict::Unknown:
            return "Unknown";
        case CertificateValidator::Verdict::Valid:
            return "Valid";
        case CertificateValidator::Verdict::Expired:
            return "Expired";
        case CertificateValidator::Verdict::Revoked:
            return "Revoked";
        case CertificateValidator::Verdict::Untrusted:
            return "Untrusted";
        case CertificateValidator::Verdict::InconsistentChain:
            return "InconsistentChain";
        case CertificateValidator::Verdict::OutsideRegion:
            return "OutsideRegion";
        case CertificateValidator::Verdict::InsufficientPermission:
            return "InsufficientPermission";
        case CertificateValidator::Verdict::Misconfiguration:
            return "Misconfiguration";
    }

    return "UnknownVerdict";
}

CertificateValidator::Verdict evaluate(
    const Certificate& root,
    const Certificate& aa,
    const Certificate& ticket,
    const std::string& reference_time,
    ItsAid application,
    bool trust_root,
    bool insert_root_issuer,
    bool insert_aa_issuer)
{
    // All dependencies remain alive for the complete validator invocation.
    TrustStore trust_store;

    if (trust_root) {
        trust_store.insert(root);
    }

    IssuerMemoryLookup issuer_lookup;

    if (insert_root_issuer && !issuer_lookup.insert(root)) {
        throw std::runtime_error("failed to insert Root in IssuerMemoryLookup");
    }

    if (insert_aa_issuer && !issuer_lookup.insert(aa)) {
        throw std::runtime_error("failed to insert AA in IssuerMemoryLookup");
    }

    // Empty in-memory revocation data: this exercises the lookup path,
    // but is not evidence that an ETSI-signed CRL has been validated.
    RevocationMemoryLookup revocation_lookup;

    ManualRuntime runtime(Clock::at(reference_time));

    StoredPositionProvider position_provider;
    PositionFix position;

    position.timestamp = runtime.now();

    // Synthetic test coordinate inside the broad SUMO scenario bounds.
    // It is NOT claimed to be the actual position of SUMO vehicle 0.
    position.latitude = 41.4 * vanetza::units::degree;
    position.longitude = -8.6 * vanetza::units::degree;

    position_provider.position_fix(position);

    DefaultLocationChecker location_checker;

    DefaultCertificateValidator validator;
    validator.use_runtime(&runtime);
    validator.use_position_provider(&position_provider);
    validator.use_location_checker(&location_checker);
    validator.use_trust_store(&trust_store);
    validator.use_issuer_lookup(&issuer_lookup);
    validator.use_revocation_lookup(&revocation_lookup);

    // No disable_* calls: time, location and chain consistency remain active.
    return validator.valid_for_signing(ticket, application);
}

struct TestSummary
{
    unsigned passed = 0;
    unsigned failed = 0;
};

void expect(
    TestSummary& summary,
    const std::string& name,
    CertificateValidator::Verdict actual,
    CertificateValidator::Verdict expected)
{
    const bool pass = actual == expected;

    std::cout
        << "CASE=" << name
        << "|EXPECTED=" << verdict_name(expected)
        << "|ACTUAL=" << verdict_name(actual)
        << "|RESULT=" << (pass ? "PASS" : "FAIL")
        << '\n';

    if (pass) {
        ++summary.passed;
    } else {
        ++summary.failed;
    }
}

} // namespace

int main(int argc, char** argv)
{
    try {
        if (argc != 4) {
            std::cerr
                << "Usage: " << argv[0]
                << " ROOT.cert AA.cert AT.cert\n";
            return 2;
        }

        const Certificate root = load_certificate(argv[1]);
        const Certificate aa = load_certificate(argv[2]);
        const Certificate ticket = load_certificate(argv[3]);

        std::cout << "OER_DECODE=PASS\n";
        std::cout << "ASN1_VALIDATION=PASS\n";

        const auto test_time = Clock::at("2026-11-22 21:30:00");

        std::cout
            << "ROOT_IS_CA=" << root.is_ca_certificate() << '\n'
            << "ROOT_IS_SELF_ISSUED=" << root.issuer_is_self() << '\n'
            << "AA_IS_CA=" << aa.is_ca_certificate() << '\n'
            << "AT_IS_TICKET=" << ticket.is_at_certificate() << '\n'
            << "ROOT_VALID_AT_TEST_TIME="
            << root.valid_at_timepoint(test_time) << '\n'
            << "AA_VALID_AT_TEST_TIME="
            << aa.valid_at_timepoint(test_time) << '\n'
            << "AT_VALID_AT_TEST_TIME="
            << ticket.valid_at_timepoint(test_time) << '\n';

        std::cout
            << "ROOT_REGION_RESTRICTION="
            << (root.has_region_restriction() ? "PRESENT" : "ABSENT") << '\n'
            << "AA_REGION_RESTRICTION="
            << (aa.has_region_restriction() ? "PRESENT" : "ABSENT") << '\n'
            << "AT_REGION_RESTRICTION="
            << (ticket.has_region_restriction() ? "PRESENT" : "ABSENT") << '\n'
            << "LOCATION_CHECKER=DefaultLocationChecker\n"
            << "LOCATION_FIXTURE=41.4,-8.6\n"
            << "LOCATION_FIXTURE_IS_ACTUAL_SUMO_POSITION=NO\n"
            << "REVOCATION_LOOKUP=EMPTY_IN_MEMORY_LOOKUP\n";

        if (!root.is_ca_certificate() ||
            !root.issuer_is_self() ||
            !aa.is_ca_certificate() ||
            !ticket.is_at_certificate()) {
            throw std::runtime_error("certificate role/type contract failed");
        }

        TestSummary summary;

        const auto valid_cam = evaluate(
            root, aa, ticket,
            "2026-11-22 21:30:00",
            static_cast<ItsAid>(36),
            true, true, true);

        expect(summary, "CAM_AID36", valid_cam,
               CertificateValidator::Verdict::Valid);

        const auto valid_denm = evaluate(
            root, aa, ticket,
            "2026-11-22 21:30:00",
            static_cast<ItsAid>(37),
            true, true, true);

        expect(summary, "DENM_AID37", valid_denm,
               CertificateValidator::Verdict::Valid);

        const auto untrusted_root = evaluate(
            root, aa, ticket,
            "2026-11-22 21:30:00",
            static_cast<ItsAid>(36),
            false, true, true);

        expect(summary, "EMPTY_TRUST_STORE", untrusted_root,
               CertificateValidator::Verdict::Untrusted);

        const auto broken_chain = evaluate(
            root, aa, ticket,
            "2026-11-22 21:30:00",
            static_cast<ItsAid>(36),
            true, true, false);

        expect(summary, "MISSING_AA_ISSUER", broken_chain,
               CertificateValidator::Verdict::Untrusted);

        const auto unauthorized_aid = evaluate(
            root, aa, ticket,
            "2026-11-22 21:30:00",
            static_cast<ItsAid>(9999),
            true, true, true);

        expect(summary, "UNAUTHORIZED_AID_9999", unauthorized_aid,
               CertificateValidator::Verdict::InsufficientPermission);

        const auto before_validity = evaluate(
            root, aa, ticket,
            "2026-11-22 20:00:00",
            static_cast<ItsAid>(36),
            true, true, true);

        expect(summary, "BEFORE_VALIDITY_START", before_validity,
               CertificateValidator::Verdict::Expired);

        const auto after_expiry = evaluate(
            root, aa, ticket,
            "2027-01-01 00:00:00",
            static_cast<ItsAid>(36),
            true, true, true);

        expect(summary, "AFTER_AT_EXPIRY", after_expiry,
               CertificateValidator::Verdict::Expired);

        std::cout
            << "VALIDATOR_CASES_PASS=" << summary.passed << '\n'
            << "VALIDATOR_CASES_FAIL=" << summary.failed << '\n'
            << "DEFAULT_CERTIFICATE_VALIDATOR="
            << (summary.failed == 0 ? "PASS" : "FAIL") << '\n';

        return summary.failed == 0 ? 0 : 1;
    }
    catch (const std::exception& error) {
        std::cerr << "[ERROR] " << error.what() << '\n';
        return 1;
    }
}
