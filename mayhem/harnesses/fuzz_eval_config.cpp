// .ovpn client profile: ClientAPI eval_config + merge_config_string (client/ovpncli.cpp).
// Reaches OptionList::parse_from_config, ParseClientConfig, RemoteList, inline blocks, Unicode checks.
#include "fuzz_common.hpp"
#include <client/ovpncli.cpp>

using namespace openvpn;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // OpenVPNClientHelper holds only the process-wide init (InitProcess); it keeps no per-input state.
    static ClientAPI::OpenVPNClientHelper helper;
    ClientAPI::Config cfg;
    cfg.content.assign(reinterpret_cast<const char *>(data), size);
    ClientAPI::EvalConfig ev = helper.eval_config(cfg);
    (void)ev;
    ClientAPI::MergeConfig mc = helper.merge_config_string(cfg.content);
    (void)mc;
    return 0;
}
