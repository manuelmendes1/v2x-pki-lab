#ifdef VANETZA_WITH_PQC
#error "This issuer must be compiled against Vanetza's standard ASN.1 security profile"
#endif

#include <vanetza/asn1/security_profile.hpp>
#include VANETZA_ASN1_SECURITY_HEADER(Signature.h)
#include VANETZA_ASN1_SECURITY_HEADER(ToBeSignedCertificate.h)
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/support/OCTET_STRING.h>
#include <vanetza/common/clock.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/hash_algorithm.hpp>
#include <vanetza/security/private_key.hpp>
#include <vanetza/security/signature.hpp>
#include <vanetza/security/v3/asn1_conversions.hpp>
#include <vanetza/security/v3/basic_elements.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/hash.hpp>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/obj_mac.h>

#include <boost/date_time/posix_time/posix_time.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace fs = std::filesystem;
namespace aid = vanetza::aid;
namespace sec = vanetza::security;
namespace v3 = vanetza::security::v3;

using vanetza::ByteBuffer;
using vanetza::Clock;
using vanetza::ItsAid;
using vanetza::security::Backend;
using vanetza::security::HashAlgorithm;
using vanetza::security::PrivateKey;
using vanetza::security::Signature;
using vanetza::security::ecdsa256::KeyPair;
using v3::Certificate;

namespace {

constexpr int kMaxValidityDays = std::numeric_limits<unsigned short>::max() / 24;
constexpr int kDefaultRootDays = 365;
constexpr int kDefaultAaDays = 180;
constexpr int kDefaultTicketDays = 30;
constexpr unsigned kDefaultVehicles = 1;

struct Options {
    fs::path lab_root;
    unsigned vehicles = kDefaultVehicles;
    unsigned start_index = 0;
    int root_days = kDefaultRootDays;
    int aa_days = kDefaultAaDays;
    int ticket_days = kDefaultTicketDays;
    std::string vehicle_prefix = "veh";
    bool execute = false;
    bool help = false;
};

struct TicketArtifact {
    std::string vehicle_id;
    KeyPair key_pair;
    Certificate certificate;
};

void usage(std::ostream& out)
{
    out <<
        "Vanetza standard-profile V3 vehicle PKI issuer\n\n"
        "Usage:\n"
        "  standard-v3-issuer [options]\n\n"
        "Options:\n"
        "  --lab-root PATH          PKI lab root (default: ~/final/v2x-pki-lab)\n"
        "  --vehicles N             Number of ATs to issue (default: 1)\n"
        "  --start-index N          First vehicle index (default: 0)\n"
        "  --vehicle-prefix PREFIX  Vehicle ID prefix (default: veh)\n"
        "  --root-days N            Root validity, 1..2730 days (default: 365)\n"
        "  --aa-days N              AA validity, <= root (default: 180)\n"
        "  --ticket-days N          AT validity, <= AA (default: 30)\n"
        "  --dry-run                Print plan only; this is the default\n"
        "  --execute                Generate a new immutable issuance run\n"
        "  --help                   Show this help\n\n"
        "The issuer never overwrites an existing run. Private keys are written as\n"
        "unencrypted PKCS#8 PEM with mode 0600, inside a mode-0700 run directory.\n";
}

std::string env_home()
{
    const char* home = std::getenv("HOME");
    if (!home || !*home) {
        throw std::runtime_error("HOME is not set; pass --lab-root explicitly");
    }
    return home;
}

unsigned parse_unsigned(const std::string& value, const std::string& option)
{
    if (value.empty() || value.front() == '-') {
        throw std::invalid_argument(option + " requires a non-negative integer");
    }
    std::size_t used = 0;
    const unsigned long parsed = std::stoul(value, &used, 10);
    if (used != value.size() || parsed > std::numeric_limits<unsigned>::max()) {
        throw std::invalid_argument("invalid value for " + option + ": " + value);
    }
    return static_cast<unsigned>(parsed);
}

int parse_days(const std::string& value, const std::string& option)
{
    const unsigned parsed = parse_unsigned(value, option);
    if (parsed < 1 || parsed > static_cast<unsigned>(kMaxValidityDays)) {
        throw std::invalid_argument(option + " must be between 1 and " +
                                    std::to_string(kMaxValidityDays));
    }
    return static_cast<int>(parsed);
}

bool safe_prefix(const std::string& value)
{
    if (value.empty() || value.size() > 24) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == '_' || c == '-';
    });
}

Options parse_options(int argc, char** argv)
{
    Options options;
    options.lab_root = fs::path(env_home()) / "final" / "v2x-pki-lab";

    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        auto take_value = [&](const char* name) -> std::string {
            if (i + 1 >= argc) {
                throw std::invalid_argument(std::string(name) + " requires a value");
            }
            return argv[++i];
        };

        if (arg == "--help" || arg == "-h") {
            options.help = true;
        } else if (arg == "--lab-root") {
            options.lab_root = take_value("--lab-root");
        } else if (arg == "--vehicles") {
            options.vehicles = parse_unsigned(take_value("--vehicles"), "--vehicles");
        } else if (arg == "--start-index") {
            options.start_index = parse_unsigned(take_value("--start-index"), "--start-index");
        } else if (arg == "--vehicle-prefix") {
            options.vehicle_prefix = take_value("--vehicle-prefix");
        } else if (arg == "--root-days") {
            options.root_days = parse_days(take_value("--root-days"), "--root-days");
        } else if (arg == "--aa-days") {
            options.aa_days = parse_days(take_value("--aa-days"), "--aa-days");
        } else if (arg == "--ticket-days") {
            options.ticket_days = parse_days(take_value("--ticket-days"), "--ticket-days");
        } else if (arg == "--execute") {
            options.execute = true;
        } else if (arg == "--dry-run") {
            options.execute = false;
        } else {
            throw std::invalid_argument("unknown option: " + arg);
        }
    }

    if (options.help) return options;
    if (options.vehicles < 1 || options.vehicles > 10000) {
        throw std::invalid_argument("--vehicles must be between 1 and 10000");
    }
    if (options.start_index > 999999U ||
        options.vehicles - 1U > 999999U - options.start_index) {
        throw std::invalid_argument("vehicle index range exceeds 0..999999");
    }
    if (!safe_prefix(options.vehicle_prefix)) {
        throw std::invalid_argument("--vehicle-prefix may contain only letters, digits, '_' and '-'");
    }
    if (options.aa_days > options.root_days) {
        throw std::invalid_argument("AA validity must not exceed Root validity");
    }
    if (options.ticket_days > options.aa_days) {
        throw std::invalid_argument("AT validity must not exceed AA validity");
    }
    options.lab_root = fs::absolute(options.lab_root).lexically_normal();
    return options;
}

void require_lab_layout(const fs::path& lab_root)
{
    if (!fs::is_regular_file(lab_root / "config" / "domains" / "vehicle-v3.yaml")) {
        throw std::runtime_error("vehicle-v3 domain config not found under lab root: " + lab_root.string());
    }
    if (!fs::is_directory(lab_root / "pki" / "domains" / "vehicle-v3")) {
        throw std::runtime_error("vehicle-v3 PKI domain directory not found under lab root");
    }
}

std::string utc_stamp()
{
    const std::time_t now = std::time(nullptr);
    std::tm tm_utc{};
    if (!gmtime_r(&now, &tm_utc)) {
        throw std::runtime_error("cannot convert current time to UTC");
    }
    char buffer[32]{};
    if (std::strftime(buffer, sizeof(buffer), "%Y%m%dT%H%M%SZ", &tm_utc) == 0) {
        throw std::runtime_error("cannot format UTC timestamp");
    }
    return buffer;
}

std::string random_suffix()
{
    std::random_device random;
    std::ostringstream stream;
    stream << std::hex << std::setfill('0') << std::setw(8)
           << static_cast<unsigned>(random());
    return stream.str();
}

void make_private_directory(const fs::path& path)
{
    fs::create_directories(path);
    if (::chmod(path.c_str(), S_IRWXU) != 0) {
        throw std::runtime_error("cannot set mode 0700 on directory " + path.string() +
                                 ": " + std::strerror(errno));
    }
}

void write_bytes(const fs::path& path, const ByteBuffer& bytes, mode_t mode)
{
    if (bytes.empty()) {
        throw std::runtime_error("refusing to write empty file: " + path.string());
    }
    std::ofstream output(path, std::ios::binary | std::ios::out | std::ios::trunc);
    if (!output) {
        throw std::runtime_error("cannot create file: " + path.string());
    }
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    output.flush();
    if (!output.good()) {
        throw std::runtime_error("failed writing file: " + path.string());
    }
    output.close();
    if (::chmod(path.c_str(), mode) != 0) {
        throw std::runtime_error("cannot set file permissions: " + path.string());
    }
}

void write_private_key_pem(const fs::path& path, const KeyPair& key_pair)
{
    if (key_pair.private_key.key.size() != 32) {
        throw std::runtime_error("generated private key is not NIST P-256");
    }

    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM* private_bn = BN_bin2bn(key_pair.private_key.key.data(),
                                   static_cast<int>(key_pair.private_key.key.size()), nullptr);
    BN_CTX* bn_context = BN_CTX_new();
    EC_POINT* public_point = nullptr;
    EVP_PKEY* evp_key = nullptr;
    BIO* bio = nullptr;
    int fd = -1;

    auto cleanup = [&]() {
        if (bio) BIO_free_all(bio);
        else if (fd >= 0) ::close(fd);
        if (evp_key) EVP_PKEY_free(evp_key);
        if (ec_key) EC_KEY_free(ec_key);
        if (public_point) EC_POINT_free(public_point);
        if (bn_context) BN_CTX_free(bn_context);
        if (private_bn) BN_clear_free(private_bn);
    };

    try {
        if (!ec_key || !private_bn || !bn_context) {
            throw std::runtime_error("OpenSSL allocation failed while preparing private key");
        }
        const EC_GROUP* group = EC_KEY_get0_group(ec_key);
        public_point = EC_POINT_new(group);
        if (!public_point || EC_KEY_set_private_key(ec_key, private_bn) != 1 ||
            EC_POINT_mul(group, public_point, private_bn, nullptr, nullptr, bn_context) != 1 ||
            EC_KEY_set_public_key(ec_key, public_point) != 1 || EC_KEY_check_key(ec_key) != 1) {
            throw std::runtime_error("cannot construct a valid P-256 OpenSSL key");
        }

        // Check that the public coordinates represented in Vanetza's key pair
        // correspond to the private scalar before exporting the PEM.
        BIGNUM* x = BN_new();
        BIGNUM* y = BN_new();
        std::array<unsigned char, 32> x_bytes{};
        std::array<unsigned char, 32> y_bytes{};
        const bool point_ok = x && y &&
            EC_POINT_get_affine_coordinates(group, public_point, x, y, bn_context) == 1 &&
            BN_bn2binpad(x, x_bytes.data(), static_cast<int>(x_bytes.size())) ==
                static_cast<int>(x_bytes.size()) &&
            BN_bn2binpad(y, y_bytes.data(), static_cast<int>(y_bytes.size())) ==
                static_cast<int>(y_bytes.size());
        if (x) BN_free(x);
        if (y) BN_free(y);
        if (!point_ok ||
            !std::equal(x_bytes.begin(), x_bytes.end(), key_pair.public_key.x.begin()) ||
            !std::equal(y_bytes.begin(), y_bytes.end(), key_pair.public_key.y.begin())) {
            throw std::runtime_error("generated P-256 private/public key pair is inconsistent");
        }

        evp_key = EVP_PKEY_new();
        if (!evp_key || EVP_PKEY_assign_EC_KEY(evp_key, ec_key) != 1) {
            throw std::runtime_error("cannot wrap P-256 key in EVP_PKEY");
        }
        ec_key = nullptr; // ownership transferred to EVP_PKEY

        fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, S_IRUSR | S_IWUSR);
        if (fd < 0) {
            throw std::runtime_error("cannot create private-key file " + path.string() +
                                     ": " + std::strerror(errno));
        }
        bio = BIO_new_fd(fd, BIO_CLOSE);
        if (!bio) {
            throw std::runtime_error("cannot create OpenSSL BIO for " + path.string());
        }
        fd = -1; // BIO owns fd
        if (PEM_write_bio_PrivateKey(bio, evp_key, nullptr, nullptr, 0, nullptr, nullptr) != 1 ||
            BIO_flush(bio) != 1) {
            throw std::runtime_error("OpenSSL failed writing PKCS#8 PEM private key: " + path.string());
        }
        BIO_free_all(bio);
        bio = nullptr;
        EVP_PKEY_free(evp_key);
        evp_key = nullptr;
        BN_clear_free(private_bn);
        private_bn = nullptr;
        BN_CTX_free(bn_context);
        bn_context = nullptr;
        EC_POINT_free(public_point);
        public_point = nullptr;
    } catch (...) {
        cleanup();
        throw;
    }
}

void assign_octets(OCTET_STRING_t& destination, const ByteBuffer& source)
{
    if (source.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
        OCTET_STRING_fromBuf(&destination,
            reinterpret_cast<const char*>(source.data()),
            static_cast<int>(source.size())) != 0) {
        throw std::runtime_error("cannot allocate ASN.1 OCTET STRING");
    }
}

PrivateKey to_v3_private_key(const vanetza::security::ecdsa256::PrivateKey& input)
{
    PrivateKey output;
    output.type = vanetza::security::KeyType::NistP256;
    output.key.assign(input.key.begin(), input.key.end());
    return output;
}

void set_verification_key(Certificate& certificate,
                          const vanetza::security::ecdsa256::PublicKey& public_key)
{
    auto& indicator = certificate->toBeSigned.verifyKeyIndicator;
    indicator.present = Vanetza_Security_VerificationKeyIndicator_PR_verificationKey;
    auto& verification_key = indicator.choice.verificationKey;
    verification_key.present = Vanetza_Security_PublicVerificationKey_PR_ecdsaNistP256;
    verification_key.choice.ecdsaNistP256 =
        v3::to_asn1(vanetza::security::compress_public_key(public_key));
}

void set_encryption_key(Certificate& certificate,
                        const vanetza::security::ecdsa256::PublicKey& public_key)
{
    certificate->toBeSigned.encryptionKey =
        vanetza::asn1::allocate<v3::asn1::PublicEncryptionKey>();
    auto& encryption_key = certificate->toBeSigned.encryptionKey->publicKey;
    encryption_key.present = Vanetza_Security_BasePublicEncryptionKey_PR_eciesNistP256;
    encryption_key.choice.eciesNistP256 =
        v3::to_asn1(vanetza::security::compress_public_key(public_key));
}

void set_issuer(Certificate& certificate, const Certificate* issuer)
{
    if (!issuer) {
        certificate->issuer.present = Vanetza_Security_IssuerIdentifier_PR_self;
        certificate->issuer.choice.self = Vanetza_Security_HashAlgorithm_sha256;
        return;
    }
    const auto digest = issuer->calculate_digest();
    if (!digest) {
        throw std::invalid_argument("issuer certificate has no canonical digest");
    }
    certificate->issuer.present = Vanetza_Security_IssuerIdentifier_PR_sha256AndDigest;
    assign_octets(certificate->issuer.choice.sha256AndDigest,
                  ByteBuffer(digest->begin(), digest->end()));
}

void set_subject_name(Certificate& certificate, const std::string& name)
{
    if (name.empty()) throw std::invalid_argument("CA subject name must not be empty");
    certificate->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_name;
    const ByteBuffer bytes(name.begin(), name.end());
    assign_octets(certificate->toBeSigned.id.choice.name, bytes);
}

void initialize_certificate(Certificate& certificate,
                            const vanetza::security::ecdsa256::PublicKey& subject_key,
                            const Certificate* issuer, int validity_days,
                            Clock::time_point now)
{
    if (validity_days < 1 || validity_days > kMaxValidityDays) {
        throw std::invalid_argument("validity must be between 1 and " +
                                    std::to_string(kMaxValidityDays) + " days");
    }
    certificate->version = 3;
    certificate->type = Vanetza_Security_CertificateType_explicit;
    set_issuer(certificate, issuer);
    const std::array<char, 3> craca_id{{0, 0, 0}};
    assign_octets(certificate->toBeSigned.cracaId,
                  ByteBuffer(craca_id.begin(), craca_id.end()));
    certificate->toBeSigned.crlSeries = 0;
    certificate->toBeSigned.validityPeriod.start =
        v3::convert_time32(now - std::chrono::hours(1));
    certificate->toBeSigned.validityPeriod.duration.present =
        Vanetza_Security_Duration_PR_hours;
    certificate->toBeSigned.validityPeriod.duration.choice.hours =
        static_cast<unsigned short>(validity_days * 24);
    set_verification_key(certificate, subject_key);
}

void add_vehicle_issue_permissions(Certificate& certificate)
{
    auto* group = vanetza::asn1::allocate<v3::asn1::PsidGroupPermissions>();
    group->subjectPermissions.present =
        Vanetza_Security_SubjectPermissions_PR_explicit;

    // Preserve the established Vanetza V3 CAM/DENM SSP ranges. These are
    // issuer permissions, not application permissions on the AT itself.
    v3::add_psid_group_permission(
        group, aid::CA, ByteBuffer{0x01, 0xff, 0xfc}, ByteBuffer{0xff, 0x00, 0x03});
    v3::add_psid_group_permission(
        group, aid::DEN, ByteBuffer{0x01, 0xff, 0xff, 0xff},
        ByteBuffer{0xff, 0x00, 0x00, 0x00});
    certificate.add_cert_issue_permission(group);
}

void add_dual_application_permissions(Certificate& certificate)
{
    // The runtime checks PSID presence. These SSP defaults match the existing
    // Vanetza V3 ECC certificate builder for CAM and DENM.
    certificate.add_app_permission(aid::CA, ByteBuffer{0x01, 0x00, 0x00});
    certificate.add_app_permission(aid::DEN, ByteBuffer{0x01, 0x00, 0x00, 0x00});
}

ByteBuffer calculate_primary_certificate_digest(Backend& backend,
                                                 HashAlgorithm algorithm,
                                                 const Certificate& subject,
                                                 const Certificate* issuer)
{
    if (algorithm == HashAlgorithm::Unspecified) {
        throw std::invalid_argument("certificate signature hash algorithm is unspecified");
    }

    if (subject.issuer_is_self() && issuer) {
        throw std::invalid_argument("self-signed certificate must not have an external issuer");
    }
    if (!subject.issuer_is_self() && !issuer) {
        throw std::invalid_argument("non-self-signed certificate requires its issuer");
    }

    auto canonical_subject = subject.canonicalize();
    if (!canonical_subject) {
        throw std::invalid_argument("subject certificate cannot be canonicalized");
    }
    const ByteBuffer tbs_input = vanetza::asn1::encode_oer(
        asn_DEF_Vanetza_Security_ToBeSignedCertificate,
        &canonical_subject->content()->toBeSigned);

    ByteBuffer issuer_input;
    if (!subject.issuer_is_self()) {
        const auto expected = subject.issuer_digest();
        const auto actual = issuer->calculate_digest();
        if (!expected || !actual || *expected != *actual) {
            throw std::invalid_argument("issuer digest does not match supplied issuer certificate");
        }
        auto canonical_issuer = issuer->canonicalize();
        if (!canonical_issuer) {
            throw std::invalid_argument("issuer certificate cannot be canonicalized");
        }
        issuer_input = canonical_issuer->encode();
    }

    const ByteBuffer data_hash = backend.calculate_hash(algorithm, tbs_input);
    const ByteBuffer issuer_hash = backend.calculate_hash(algorithm, issuer_input);
    ByteBuffer concatenated;
    concatenated.reserve(data_hash.size() + issuer_hash.size());
    concatenated.insert(concatenated.end(), data_hash.begin(), data_hash.end());
    concatenated.insert(concatenated.end(), issuer_hash.begin(), issuer_hash.end());
    return backend.calculate_hash(algorithm, concatenated);
}

void set_primary_signature(Certificate& certificate, const Signature& signature)
{
    if (signature.r.size() != vanetza::security::key_length(signature.type) ||
        signature.s.size() != vanetza::security::key_length(signature.type)) {
        throw std::invalid_argument("ECC certificate signature has an invalid component size");
    }

    if (certificate->signature) {
        vanetza::asn1::free(asn_DEF_Vanetza_Security_Signature, certificate->signature);
    }
    certificate->signature = vanetza::asn1::allocate<v3::asn1::Signature>();

    v3::asn1::EccP256CurvePoint* r256 = nullptr;
    v3::asn1::EccP384CurvePoint* r384 = nullptr;
    OCTET_STRING_t* s = nullptr;
    switch (signature.type) {
        case vanetza::security::KeyType::NistP256:
            certificate->signature->present =
                Vanetza_Security_Signature_PR_ecdsaNistP256Signature;
            r256 = &certificate->signature->choice.ecdsaNistP256Signature.rSig;
            s = &certificate->signature->choice.ecdsaNistP256Signature.sSig;
            break;
        case vanetza::security::KeyType::BrainpoolP256r1:
            certificate->signature->present =
                Vanetza_Security_Signature_PR_ecdsaBrainpoolP256r1Signature;
            r256 = &certificate->signature->choice.ecdsaBrainpoolP256r1Signature.rSig;
            s = &certificate->signature->choice.ecdsaBrainpoolP256r1Signature.sSig;
            break;
        case vanetza::security::KeyType::BrainpoolP384r1:
            certificate->signature->present =
                Vanetza_Security_Signature_PR_ecdsaBrainpoolP384r1Signature;
            r384 = &certificate->signature->choice.ecdsaBrainpoolP384r1Signature.rSig;
            s = &certificate->signature->choice.ecdsaBrainpoolP384r1Signature.sSig;
            break;
        default:
            throw std::invalid_argument("unsupported ECC certificate signature type");
    }
    if (r256) {
        r256->present = Vanetza_Security_EccP256CurvePoint_PR_x_only;
        assign_octets(r256->choice.x_only, signature.r);
    } else {
        r384->present = Vanetza_Security_EccP384CurvePoint_PR_x_only;
        assign_octets(r384->choice.x_only, signature.r);
    }
    assign_octets(*s, signature.s);
}

void sign_primary_certificate(Certificate& subject, const Certificate* issuer,
                              Backend& backend,
                              const vanetza::security::ecdsa256::PrivateKey& issuer_key)
{
    const Certificate& signer = subject.issuer_is_self() ? subject : *issuer;
    const auto public_key = v3::get_public_key(*signer.content());
    if (!public_key || public_key->type != vanetza::security::KeyType::NistP256) {
        throw std::invalid_argument("issuer certificate has no supported NIST P-256 verification key");
    }

    PrivateKey private_key = to_v3_private_key(issuer_key);
    const HashAlgorithm algorithm = v3::specified_hash_algorithm(public_key->type);
    const ByteBuffer digest = calculate_primary_certificate_digest(
        backend, algorithm, subject, issuer);
    const Signature signature = backend.sign_digest(private_key, digest);
    if (!backend.verify_digest(*public_key, digest, signature)) {
        throw std::invalid_argument("issuer private key does not match issuer certificate public key");
    }
    set_primary_signature(subject, signature);
}

bool verify_primary_certificate(const Certificate& subject,
                                const Certificate* issuer, Backend& backend)
{
    try {
        const Certificate& signer = subject.issuer_is_self() ? subject : *issuer;
        const auto public_key = v3::get_public_key(*signer.content());
        const auto signature = v3::get_signature(*subject.content());
        if (!public_key || !signature || public_key->type != signature->type) return false;
        const HashAlgorithm algorithm = v3::specified_hash_algorithm(public_key->type);
        const ByteBuffer digest = calculate_primary_certificate_digest(
            backend, algorithm, subject, issuer);
        return backend.verify_digest(*public_key, digest, *signature);
    } catch (const std::exception&) {
        return false;
    }
}

Certificate canonical_certificate(Certificate certificate)
{
    auto canonical = certificate.canonicalize();
    if (!canonical) {
        throw std::runtime_error("generated V3 certificate cannot be canonicalized");
    }
    std::string error;
    if (!canonical->validate(error)) {
        throw std::runtime_error("generated V3 certificate violates ASN.1 constraints: " + error);
    }
    if (!canonical->is_canonical()) {
        throw std::runtime_error("generated V3 certificate is not in canonical form");
    }
    return std::move(*canonical);
}

Certificate build_root(Backend& backend, const KeyPair& subject_key,
                       int validity_days, Clock::time_point now)
{
    Certificate certificate;
    initialize_certificate(certificate, subject_key.public_key, nullptr,
                            validity_days, now);
    set_subject_name(certificate, "V2X Vehicle Root CA");
    add_vehicle_issue_permissions(certificate);
    certificate.add_app_permission(aid::CRL, ByteBuffer{0x01});
    certificate.add_app_permission(aid::CTL, ByteBuffer{0x18});
    sign_primary_certificate(certificate, nullptr, backend, subject_key.private_key);
    return canonical_certificate(std::move(certificate));
}

Certificate build_aa(Backend& backend, const KeyPair& issuer_key,
                     const Certificate& issuer_certificate,
                     const KeyPair& subject_key,
                     int validity_days, Clock::time_point now)
{
    Certificate certificate;
    initialize_certificate(certificate, subject_key.public_key,
                            &issuer_certificate, validity_days, now);
    set_subject_name(certificate, "V2X Vehicle Authorization Authority");
    add_vehicle_issue_permissions(certificate);
    set_encryption_key(certificate, subject_key.public_key);
    sign_primary_certificate(certificate, &issuer_certificate,
                             backend, issuer_key.private_key);
    return canonical_certificate(std::move(certificate));
}

Certificate build_ticket(Backend& backend, const KeyPair& issuer_key,
                         const Certificate& issuer_certificate,
                         const KeyPair& subject_key,
                         int validity_days, Clock::time_point now)
{
    Certificate certificate;
    initialize_certificate(certificate, subject_key.public_key,
                            &issuer_certificate, validity_days, now);
    certificate->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_none;
    add_dual_application_permissions(certificate);
    sign_primary_certificate(certificate, &issuer_certificate,
                             backend, issuer_key.private_key);
    return canonical_certificate(std::move(certificate));
}

std::string hex_bytes(const ByteBuffer& bytes)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (const auto byte : bytes) out << std::setw(2) << static_cast<unsigned>(byte);
    return out.str();
}

std::string cert_digest(const Certificate& certificate)
{
    const auto digest = certificate.calculate_digest();
    if (!digest) throw std::runtime_error("cannot calculate generated certificate HashedId8");
    return hex_bytes(ByteBuffer(digest->begin(), digest->end()));
}

void write_certificate(const fs::path& path, const Certificate& certificate)
{
    std::string error;
    if (!certificate.validate(error)) {
        throw std::runtime_error("refusing to persist ASN.1-invalid certificate: " + error);
    }
    write_bytes(path, certificate.encode(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
}

void write_text(const fs::path& path, const std::string& content, mode_t mode)
{
    std::ofstream output(path, std::ios::binary | std::ios::out | std::ios::trunc);
    if (!output) throw std::runtime_error("cannot create file: " + path.string());
    output << content;
    output.flush();
    if (!output.good()) throw std::runtime_error("failed writing file: " + path.string());
    output.close();
    if (::chmod(path.c_str(), mode) != 0) {
        throw std::runtime_error("cannot set file permissions: " + path.string());
    }
}

void validate_chain(const Certificate& root, const Certificate& aa,
                    const std::vector<TicketArtifact>& tickets,
                    Backend& backend, Clock::time_point now)
{
    if (!root.issuer_is_self() || !verify_primary_certificate(root, nullptr, backend)) {
        throw std::runtime_error("Root self-signature verification failed");
    }
    if (!aa.is_ca_certificate() || !verify_primary_certificate(aa, &root, backend)) {
        throw std::runtime_error("AA classification or Root signature verification failed");
    }
    for (const ItsAid application_id : {aid::CA, aid::DEN}) {
        if (!root.is_allowed_to_issue(application_id)) {
            throw std::runtime_error("Root is missing issue permission for ITS-AID " +
                                     std::to_string(application_id));
        }
        if (!aa.is_allowed_to_issue(application_id)) {
            throw std::runtime_error("AA is missing issue permission for ITS-AID " +
                                     std::to_string(application_id));
        }
    }
    if (!root.valid_at_timepoint(now) || !aa.valid_at_timepoint(now)) {
        throw std::runtime_error("Root or AA is not valid at issuance time");
    }

    for (const auto& ticket : tickets) {
        const Certificate& at = ticket.certificate;
        if (!at.is_at_certificate()) {
            throw std::runtime_error(ticket.vehicle_id + " is not recognized as an AT certificate");
        }
        if (!at.valid_at_timepoint(now)) {
            throw std::runtime_error(ticket.vehicle_id + " AT is not valid at issuance time");
        }
        if (!at.valid_for_application(aid::CA) || !at.valid_for_application(aid::DEN)) {
            throw std::runtime_error(ticket.vehicle_id + " AT does not authorize both AID 36 and 37");
        }
        if (!verify_primary_certificate(at, &aa, backend)) {
            throw std::runtime_error(ticket.vehicle_id + " AT primary signature verification failed");
        }
    }
}

void write_generation(const fs::path& stage, const KeyPair& root_key,
                      const Certificate& root, const KeyPair& aa_key,
                      const Certificate& aa,
                      const std::vector<TicketArtifact>& tickets,
                      const Options& options, Clock::time_point now,
                      const std::string& run_id)
{
    const fs::path root_dir = stage / "authorities" / "root";
    const fs::path aa_dir = stage / "authorities" / "aa";
    const fs::path ticket_dir = stage / "issued-tickets" / "dual-aid";
    const fs::path trust_dir = stage / "trust-store";
    const fs::path chain_dir = stage / "certificate-chain";
    make_private_directory(root_dir);
    make_private_directory(aa_dir);
    make_private_directory(ticket_dir);
    make_private_directory(trust_dir);
    make_private_directory(chain_dir);

    write_private_key_pem(root_dir / "root.pem", root_key);
    write_certificate(root_dir / "root.cert", root);
    write_private_key_pem(aa_dir / "aa.pem", aa_key);
    write_certificate(aa_dir / "aa.cert", aa);
    // Publish explicit trust and issuer-chain copies so C-02 configuration
    // does not have to infer trust material from the authority directories.
    write_certificate(trust_dir / "trusted-root.cert", root);
    write_certificate(chain_dir / "aa.cert", aa);
    write_certificate(chain_dir / "root.cert", root);

    std::ostringstream manifest;
    manifest << "format=V2X-PKI-LAB-VEHICLE-V3-ISSUANCE-1\n"
             << "run_id=" << run_id << '\n'
             << "profile=etsi-ts-103097-v3-standard-ecc\n"
             << "asn1_profile=standard\n"
             << "pqc=disabled\n"
             << "crypto_backend=OpenSSL\n"
             << "signature_algorithm=ECDSA_NIST_P256_SHA256\n"
             << "generated_vehicle_count=" << tickets.size() << '\n'
             << "authorized_application_aids=36,37\n"
             << "root_validity_days=" << options.root_days << '\n'
             << "aa_validity_days=" << options.aa_days << '\n'
             << "ticket_validity_days=" << options.ticket_days << '\n'
             << "clock_epoch=Vanetza ITS time (2004-01-01)\n"
             << "validity_start_offset_seconds=-3600\n"
             << "root_hashed_id8=" << cert_digest(root) << '\n'
             << "aa_hashed_id8=" << cert_digest(aa) << '\n'
             << "trust_anchor=trust-store/trusted-root.cert\n"
             << "issuer_chain=certificate-chain/aa.cert,certificate-chain/root.cert\n"
             << "private_key_format=PKCS8 PEM, unencrypted, filesystem mode 0600\n"
             << "private_keys_are_test_credentials=true\n"
             << "runtime_acceptance=NOT_YET_DEMONSTRATED\n"
             << "\n[tickets]\n";

    for (const auto& ticket : tickets) {
        const std::string stem = ticket.vehicle_id + "-ticket-000";
        write_private_key_pem(ticket_dir / (stem + ".pem"), ticket.key_pair);
        write_certificate(ticket_dir / (stem + ".cert"), ticket.certificate);
        manifest << ticket.vehicle_id << ".certificate_hashed_id8="
                 << cert_digest(ticket.certificate) << '\n';
    }
    write_text(stage / "manifest.txt", manifest.str(),
               S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
}

void run(const Options& options)
{
    require_lab_layout(options.lab_root);
    const fs::path domain = options.lab_root / "pki" / "domains" / "vehicle-v3";
    const fs::path runs_dir = domain / "issuance" / "runs";
    const std::string run_id = "vehicle-dual-aid-" + utc_stamp() + "-" +
                               std::to_string(::getpid()) + "-" + random_suffix();
    const fs::path final_path = runs_dir / run_id;

    std::cout << "ISSUER_PROFILE=standard\n"
              << "CRYPTO_BACKEND=OpenSSL\n"
              << "DOMAIN=vehicle-v3\n"
              << "ROOT_ISSUE_AIDS=36,37\n"
              << "AA_ISSUE_AIDS=36,37\n"
              << "AT_APPLICATION_AIDS=36,37\n"
              << "ROOT_VALIDITY_DAYS=" << options.root_days << '\n'
              << "AA_VALIDITY_DAYS=" << options.aa_days << '\n'
              << "AT_VALIDITY_DAYS=" << options.ticket_days << '\n'
              << "VEHICLE_COUNT=" << options.vehicles << '\n'
              << "VEHICLE_INDEX_RANGE=" << options.start_index << ".."
              << (options.start_index + options.vehicles - 1U) << '\n'
              << "PROPOSED_RUN=" << final_path.string() << '\n';

    if (!options.execute) {
        std::cout << "MODE=DRY_RUN\nFILES_WRITTEN=0\n"
                  << "DRY_RUN=PASS\n";
        return;
    }

    if (fs::exists(final_path)) {
        throw std::runtime_error("refusing to overwrite existing issuance run: " + final_path.string());
    }
    make_private_directory(runs_dir);
    const fs::path stage = runs_dir / (".staging-" + run_id);
    if (fs::exists(stage)) {
        throw std::runtime_error("staging path already exists: " + stage.string());
    }
    make_private_directory(stage);

    bool published = false;
    try {
        auto backend = sec::create_backend_or_throw("OpenSSL");
        const Clock::time_point now = Clock::at(
            boost::posix_time::microsec_clock::universal_time());

        const KeyPair root_key = backend->generate_key_pair();
        Certificate root = build_root(*backend, root_key, options.root_days, now);

        const KeyPair aa_key = backend->generate_key_pair();
        Certificate aa = build_aa(*backend, root_key, root, aa_key,
                                  options.aa_days, now);

        std::vector<TicketArtifact> tickets;
        tickets.reserve(options.vehicles);
        for (unsigned offset = 0; offset < options.vehicles; ++offset) {
            const unsigned index = options.start_index + offset;
            std::ostringstream vehicle;
            vehicle << options.vehicle_prefix << index;
            KeyPair ticket_key = backend->generate_key_pair();
            Certificate ticket = build_ticket(*backend, aa_key, aa, ticket_key,
                                              options.ticket_days, now);
            tickets.push_back(TicketArtifact{
                vehicle.str(), std::move(ticket_key), std::move(ticket)});
        }

        validate_chain(root, aa, tickets, *backend, now);
        write_generation(stage, root_key, root, aa_key, aa, tickets,
                         options, now, run_id);

        // Publish the complete generation with one same-filesystem rename.
        fs::rename(stage, final_path);
        published = true;

        std::cout << "ROOT_SELF_SIGNATURE=PASS\n"
                  << "AA_BY_ROOT_SIGNATURE=PASS\n"
                  << "AT_SIGNATURES_PASS=" << tickets.size() << '\n'
                  << "DUAL_AID_POLICY=PASS\n"
                  << "ASN1_VALIDATION=PASS\n"
                  << "GENERATION_PUBLISHED=" << final_path.string() << '\n'
                  << "PRIVATE_KEY_MODE=0600\n"
                  << "RUN_DIRECTORY_MODE=0700\n"
                  << "RUNTIME_ACCEPTANCE=NOT_YET_DEMONSTRATED\n"
                  << "ISSUANCE=PASS\n";
    } catch (...) {
        if (!published) {
            std::error_code ignored;
            fs::remove_all(stage, ignored);
        }
        throw;
    }
}

} // namespace

int main(int argc, char** argv)
{
    try {
        const Options options = parse_options(argc, argv);
        if (options.help) {
            usage(std::cout);
            return 0;
        }
        run(options);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << '\n';
        return 2;
    }
}
