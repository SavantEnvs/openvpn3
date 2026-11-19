// HTTP/WebSocket parsing of untrusted peers: HTTP::ReplyParser (proxy CONNECT replies, web
// client), HTTP::RequestParser (web server), WS::ChunkedHelper (chunked transfer bodies) and
// WebSocket::Receiver (frames). First byte selects the parser.
#include "fuzz_common.hpp"
#include <openvpn/http/reply.hpp>
#include <openvpn/http/request.hpp>
#include <openvpn/ws/chunked.hpp>
#include <openvpn/ws/websocket.hpp>

using namespace openvpn;

namespace {
struct ChunkSink
{
    size_t total = 0;
    void chunked_content_in(BufferAllocated &buf)
    {
        total += buf.size();
    }
};
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return 0;
    const uint8_t sel = data[0] % 5;
    data++;
    size--;
    try
    {
        switch (sel)
        {
        case 0:
            {
                HTTP::Reply reply;
                HTTP::ReplyParser parser;
                for (size_t i = 0; i < size; ++i)
                {
                    const auto st = parser.consume(reply, data[i]);
                    if (st == HTTP::ReplyParser::fail)
                        break;
                    if (st == HTTP::ReplyParser::success)
                    {
                        (void)reply.to_string();
                        (void)reply.headers.get_value_trim("content-length");
                        (void)reply.headers.get_value_trim("proxy-authenticate");
                        reply.reset();
                        parser.reset();
                    }
                }
                break;
            }
        case 1:
            {
                HTTP::Request req;
                HTTP::RequestParser parser;
                for (size_t i = 0; i < size; ++i)
                {
                    const auto st = parser.consume(req, data[i]);
                    if (st == HTTP::RequestParser::fail)
                        break;
                    if (st == HTTP::RequestParser::success)
                    {
                        (void)req.to_string();
                        (void)req.headers.get_value_trim("host");
                        req.reset();
                        parser.reset();
                    }
                }
                break;
            }
        case 2:
            {
                WS::ChunkedHelper ch;
                ChunkSink sink;
                size_t off = 0;
                while (off < size)
                {
                    const size_t n = std::min<size_t>(size - off, 1 + (data[off] & 0x3f));
                    BufferAllocated buf(data + off, n, BufAllocFlags::NO_FLAGS);
                    off += n;
                    if (ch.receive(sink, buf))
                        break;
                }
                break;
            }
        default:
            {
                // 3: client side (server->client frames, unmasked); 4: server side (masked)
                WebSocket::Receiver rx(sel == 3);
                size_t off = 0;
                while (off < size)
                {
                    const size_t n = std::min<size_t>(size - off, 1 + (data[off] & 0x3f));
                    BufferAllocated buf(data + off, n, BufAllocFlags::NO_FLAGS);
                    off += n;
                    rx.add_buf(std::move(buf));
                    while (rx.complete())
                    {
                        Buffer b = rx.buf_unframed();
                        (void)b.size();
                        rx.reset();
                    }
                }
                break;
            }
        }
    }
    catch (const std::exception &)
    {
    }
    return 0;
}
