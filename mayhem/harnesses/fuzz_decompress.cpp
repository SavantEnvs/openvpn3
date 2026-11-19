// Data-channel decompression of packets from the peer: CompressContext(type).new_compressor()
// then decompress() (LZ4, LZ4v2, LZO-asym (in-tree decompressor), stub/stubv2 framing).
#include "fuzz_common.hpp"
#include <openvpn/compress/compress.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/log/sessionstats.hpp>

using namespace openvpn;

class FuzzStats : public SessionStats
{
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const bool init = (CompressContext::init_static(), true);
    (void)init;
    if (size < 1)
        return 0;
    static const CompressContext::Type types[] = {
        CompressContext::LZ4,
        CompressContext::LZ4v2,
        CompressContext::LZO_STUB,
        CompressContext::COMP_STUB,
        CompressContext::COMP_STUBv2,
        CompressContext::LZO,
        CompressContext::LZO_SWAP,
        CompressContext::ANY,
    };
    const CompressContext::Type t = types[data[0] % (sizeof(types) / sizeof(types[0]))];
    const bool asym = data[0] & 0x80;
    data++;
    size--;

    Frame::Ptr frame(new Frame(Frame::Context(512, 1500, 512, 0, 16, BufAllocFlags::NO_FLAGS)));
    frame->standardize_capacity(~0);
    SessionStats::Ptr stats(new FuzzStats);
    try
    {
        CompressContext cc(t, asym);
        Compress::Ptr c = cc.new_compressor(frame, stats);
        BufferAllocated buf;
        frame->prepare(Frame::DECRYPT_WORK, buf);
        if (size > buf.remaining())
            size = buf.remaining();
        buf.write(data, size);
        c->decompress(buf);
    }
    catch (const std::exception &)
    {
    }
    return 0;
}
