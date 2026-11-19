// Key / certificate text from a profile or a server's key directory: OpenVPNStaticKey::parse
// (tls-auth / tls-crypt / secret), TLSCryptV2ServerKey / TLSCryptV2ClientKey::parse (PEM + base64),
// OpenSSL CertCRLList / X509 / PKey parse_pem, PeerFingerprints and VerifyX509Name option parsing.
// First byte selects the parser.
#include "fuzz_common.hpp"
#include <openvpn/ssl/sslchoose.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/crypto/static_key.hpp>
#include <openvpn/crypto/tls_crypt.hpp>
#include <openvpn/crypto/tls_crypt_v2.hpp>
#include <openvpn/crypto/cryptodcsel.hpp>
#include <openvpn/openssl/pki/x509.hpp>
#include <openvpn/openssl/pki/x509store.hpp>
#include <openvpn/openssl/pki/pkey.hpp>
#include <openvpn/ssl/peer_fingerprint.hpp>
#include <openvpn/ssl/verify_x509_name.hpp>
#include <openvpn/ssl/tls_remote.hpp>
#include <openvpn/init/initprocess.hpp>

using namespace openvpn;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static InitProcess::Init init;
    if (size < 1)
        return 0;
    const uint8_t sel = data[0] % 6;
    const std::string s(reinterpret_cast<const char *>(data + 1), size - 1);
    try
    {
        switch (sel)
        {
        case 0:
            {
                OpenVPNStaticKey key;
                key.parse(s);
                (void)key.render();
                break;
            }
        case 1:
            {
                TLSCryptV2ServerKey key;
                key.parse(s);
                (void)key.render();
                break;
            }
        case 2:
            {
                TLSCryptContext::Ptr ctx(new CryptoTLSCryptContext<SSLLib::CryptoAPI>(nullptr, CryptoAlgs::SHA256, CryptoAlgs::AES_256_CTR));
                TLSCryptV2ClientKey key(ctx);
                key.parse(s);
                BufferAllocated wkc;
                key.extract_wkc(wkc);
                break;
            }
        case 3:
            {
                OpenSSLPKI::X509Store::CertCRLList ccl;
                ccl.parse_pem(s, "fuzz");
                (void)ccl.render_pem();
                break;
            }
        case 4:
            {
                OpenSSLPKI::PKey pk;
                pk.parse_pem(s, "fuzz", nullptr);
                (void)pk.render_pem();
                break;
            }
        default:
            {
                OptionList opt = OptionList::parse_from_config_static(s, nullptr);
                PeerFingerprints fps(opt, 32);
                VerifyX509Name v(opt);
                (void)v.verify("CN=server,O=OpenVPN");
                (void)TLSRemote::sanitize_x509_name(s);
                (void)TLSRemote::sanitize_common_name(s);
                break;
            }
        }
    }
    catch (const std::exception &)
    {
    }
    return 0;
}
