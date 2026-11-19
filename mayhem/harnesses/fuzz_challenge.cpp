// Server-sent auth challenge strings: CRV1 dynamic challenges (ClientAPI parse_dynamic_challenge,
// ChallengeResponse), static-challenge cookies (SCRV1) and the argv-style lexer used for
// AUTH_FAILED / INFO messages and management commands.
#include "fuzz_common.hpp"
#include <openvpn/auth/cr.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/split.hpp>

#include <openvpn/init/initprocess.hpp>

using namespace openvpn;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static InitProcess::Init init; // sets up the process-wide base64 codec, among others
    const std::string s(reinterpret_cast<const char *>(data), size);
    try
    {
        ChallengeResponse cr(s);
        (void)cr.get_challenge_text();
        (void)cr.get_state_id();
        (void)cr.get_username();
        (void)cr.construct_dynamic_password("response");
    }
    catch (const std::exception &)
    {
    }
    try
    {
        ChallengeResponse cr(s, "user");
        (void)cr.get_state_id();
    }
    catch (const std::exception &)
    {
    }
    try
    {
        std::string password, response;
        ChallengeResponse::parse_static_cookie(s, password, response);
    }
    catch (const std::exception &)
    {
    }
    try
    {
        (void)Split::by_space<std::vector<std::string>, StandardLex, SpaceMatch, Split::NullLimit>(s);
        OptionList ol = OptionList::parse_from_argv_static(
            Split::by_space<std::vector<std::string>, StandardLex, SpaceMatch, Split::NullLimit>(s));
        (void)ol.render(Option::RENDER_BRACKET);
    }
    catch (const std::exception &)
    {
    }
    return 0;
}
