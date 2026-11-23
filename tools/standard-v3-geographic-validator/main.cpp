#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security_profile.hpp>
#include VANETZA_ASN1_SECURITY_HEADER(GeographicRegion.h)
#include VANETZA_ASN1_SECURITY_HEADER(CircularRegion.h)

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
namespace v3asn = vanetza::security::v3::asn1;

using vanetza::ByteBuffer;
using vanetza::Clock;
using vanetza::ItsAid;
using vanetza::ManualRuntime;
using vanetza::PositionFix;
using vanetza::StoredPositionProvider;

using v3::Certificate;
using v3::CertificateValidator;
using v3::DefaultCertificateValidator;
using v3::DefaultLocationChecker;
using v3::IssuerMemoryLookup;
using v3::RevocationMemoryLookup;
using v3::TrustStore;

namespace
{

ByteBuffer read_file(const std::string& path)
{
    std::ifstream input(path, std::ios::binary);

    if (!input) {
        throw std::runtime_error("cannot open: " + path);
    }

    const std::vector<char> raw {
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>()
    };

    ByteBuffer bytes;
    bytes.reserve(raw.size());

    for (const char value : raw) {
        bytes.push_back(static_cast<std::uint8_t>(
            static_cast<unsigned char>(value)));
    }

    if (bytes.empty()) {
        throw std::runtime_error("empty certificate: " + path);
    }

    return bytes;
}

Certificate load_certificate(const std::string& path)
{
    Certificate cert;
    const auto bytes = read_file(path);

    if (!cert.decode(bytes)) {
        throw std::runtime_error("OER decoding failed: " + path);
    }

    std::string error;
    if (!cert.validate(error)) {
        throw std::runtime_error(
            "ASN.1 validation failed: " + path + ": " + error);
    }

    return cert;
}

const char* verdict_name(CertificateValidator::Verdict verdict)
{
    switch (verdict) {
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
        case CertificateValidator::Verdict::Unknown:
            return "Unknown";
    }

    return "UnknownVerdict";
}

void add_synthetic_circle(Certificate& certificate)
{
    if (certificate->toBeSigned.region != nullptr) {
        throw std::runtime_error(
            "expected original AT to have no region restriction");
    }

    auto* region =
        vanetza::asn1::allocate<v3asn::GeographicRegion>();

    region->present =
        Vanetza_Security_GeographicRegion_PR_circularRegion;

    auto& circle = region->choice.circularRegion;

    // ASN.1 geographic coordinates: 10^-7 degrees.
    // 41.4 degrees latitude and -8.6 degrees longitude.
    circle.center.latitude = 414000000;
    circle.center.longitude = -86000000;

    // Radius is expressed in metres.
    circle.radius = 1000;

    certificate->toBeSigned.region = region;

    std::string error;
    if (!certificate.validate(error)) {
        throw std::runtime_error(
            "synthetic geographic region violates ASN.1 constraints: "
            + error);
    }
}

CertificateValidator::Verdict evaluate(
    const Certificate& root,
    const Certificate& aa,
    const Certificate& ticket,
    double latitude,
    double longitude)
{
    TrustStore trust_store;
    trust_store.insert(root);

    IssuerMemoryLookup issuer_lookup;

    if (!issuer_lookup.insert(root)) {
        throw std::runtime_error("could not insert Root issuer");
    }

    if (!issuer_lookup.insert(aa)) {
        throw std::runtime_error("could not insert AA issuer");
    }

    RevocationMemoryLookup revocation_lookup;

    ManualRuntime runtime(
        Clock::at("2026-11-22 21:30:00"));

    PositionFix fix;
    fix.timestamp = runtime.now();
    fix.latitude = latitude * vanetza::units::degree;
    fix.longitude = longitude * vanetza::units::degree;

    StoredPositionProvider position_provider;
    position_provider.position_fix(fix);

    DefaultLocationChecker location_checker;

    DefaultCertificateValidator validator;
    validator.use_runtime(&runtime);
    validator.use_position_provider(&position_provider);
    validator.use_location_checker(&location_checker);
    validator.use_trust_store(&trust_store);
    validator.use_issuer_lookup(&issuer_lookup);
    validator.use_revocation_lookup(&revocation_lookup);

    // All validator controls remain active.
    // No disable_* calls and no permissive location checker.
    return validator.valid_for_signing(
        ticket, static_cast<ItsAid>(36));
}

struct Summary
{
    unsigned passed = 0;
    unsigned failed = 0;
};

void expect(
    Summary& summary,
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
        const Certificate original_ticket = load_certificate(argv[3]);

        std::cout << "OER_DECODE=PASS\n";
        std::cout << "ASN1_VALIDATION=PASS\n";

        if (root.has_region_restriction() ||
            aa.has_region_restriction() ||
            original_ticket.has_region_restriction()) {
            throw std::runtime_error(
                "original certificate chain unexpectedly has region restrictions");
        }

        std::cout << "ORIGINAL_CERTIFICATES_REGION_RESTRICTION=ABSENT\n";

        // Baseline: the original, unmodified ticket.
        const auto original_result = evaluate(
            root, aa, original_ticket, 41.4, -8.6);

        Summary summary;

        expect(
            summary,
            "ORIGINAL_AT_WITHOUT_REGION",
            original_result,
            CertificateValidator::Verdict::Valid);

        // Copy the AT in memory; do not alter the issued artifact.
        Certificate inside_ticket = original_ticket;
        add_synthetic_circle(inside_ticket);

        std::cout << "SYNTHETIC_CIRCLE_CENTER=41.4,-8.6\n";
        std::cout << "SYNTHETIC_CIRCLE_RADIUS_METRES=1000\n";
        std::cout << "AT_MODIFIED_IN_MEMORY=YES\n";
        std::cout << "AT_ORIGINAL_FILE_MODIFIED=NO\n";
        std::cout << "MUTATED_AT_SIGNATURE_REVALIDATED=NO\n";

        const auto inside_result = evaluate(
            root, aa, inside_ticket, 41.4, -8.6);

        expect(
            summary,
            "POSITION_INSIDE_CIRCLE",
            inside_result,
            CertificateValidator::Verdict::Valid);

        // 0.02 degrees latitude is approximately 2.2 km.
        // This is deliberately outside the 1 km synthetic circle.
        Certificate outside_ticket = original_ticket;
        add_synthetic_circle(outside_ticket);

        const auto outside_result = evaluate(
            root, aa, outside_ticket, 41.42, -8.6);

        std::cout << "OUTSIDE_TEST_POSITION=41.42,-8.6\n";

        expect(
            summary,
            "POSITION_OUTSIDE_CIRCLE",
            outside_result,
            CertificateValidator::Verdict::OutsideRegion);

        std::cout
            << "GEOGRAPHIC_CASES_PASS=" << summary.passed << '\n'
            << "GEOGRAPHIC_CASES_FAIL=" << summary.failed << '\n'
            << "DEFAULT_LOCATION_CHECKER="
            << (summary.failed == 0 ? "PASS" : "FAIL")
            << '\n';

        return summary.failed == 0 ? 0 : 1;
    }
    catch (const std::exception& error) {
        std::cerr << "[ERROR] " << error.what() << '\n';
        return 1;
    }
}
