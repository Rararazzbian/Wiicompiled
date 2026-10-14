#pragma once

// Direct-connect online. With [online] direct = true, every WFC hostname the
// game asks for resolves to a placeholder address and the runtime carries the
// traffic to a built-in WFC server run by one of the players (the host). The
// game's DWC code runs unchanged; it just talks to us.
//
// All of a runtime's WFC traffic goes through one relay port on the host:
// - TCP (NAS, GPCM, GPSP, server browser): the game connects to a loopback
//   front-end, which opens a connection to the relay prefixed with a small
//   preamble naming the service, then passes bytes through.
// - UDP (QR2, NAT negotiation, and peer-to-peer race traffic): the game's own
//   socket sends each datagram to the relay wrapped in a header naming the
//   destination; the relay hands it to the server or forwards it to the
//   destination player. Players address each other by virtual IPs
//   (10.77.0.N) that the relay assigns, so only the host needs a reachable port.
//
// Guest-visible state (WiiSocket::peerAddr, recvfrom sources, getpeername)
// only ever carries the placeholder address, virtual IPs and the ports the
// guest used; rewriting happens at the native call boundary.

#include "network_internal.h"

namespace NetworkHle::DirectOnline {

// 192.0.2.1 (TEST-NET-1, RFC 5737): never routable, so a rewrite that is missed
// fails loudly instead of reaching a real host. Host byte order.
inline constexpr uint32_t kPlaceholderIp = 0xC0000201u;

bool Enabled();

// Direct-mode log line, always on while direct mode is active: it is the only
// view of what the game asks the built-in server for.
void Log(const char* format, ...);

// True for every hostname the DWC/GameSpy SDK uses for WFC services
// (*.nintendowifi.net, *.gamespy.com).
bool IsWfcHost(std::string_view hostname);

// Bring-up diagnostic: times one synchronous network ioctl on the emulation
// thread and, in direct mode, logs it if it blocked the game for too long.
// Adds players who arrived on the host to the friend list while online.
// Called on the emulation thread from every network ioctl; cheap when
// nothing changed.
void FriendListTick();

class SlowCallProbe {
public:
    SlowCallProbe(const char* device, uint32_t cmd);
    ~SlowCallProbe();
    SlowCallProbe(const SlowCallProbe&) = delete;
    SlowCallProbe& operator=(const SlowCallProbe&) = delete;

private:
    const char* device_;
    uint32_t cmd_;
    std::chrono::steady_clock::time_point start_;
};

// TCP connect, guest -> native: a placeholder destination becomes the matching
// loopback front-end, starting direct mode on first use. Returns false
// (address left untouched) for anything else.
bool ToNative(sockaddr_in& address);

// getpeername, native -> guest: a loopback front-end address becomes the
// placeholder address and the WFC port the guest originally used.
bool ToGuest(sockaddr_in& address);

// UDP send: a datagram for the placeholder address or a virtual IP is wrapped
// for the relay. On true, `wrapped` holds the bytes to send and `nativeDest`
// the relay address. `native` is the sending socket (bound here if it is not
// yet, since the relay needs its port).
bool WrapDatagram(NativeSocket native, const sockaddr_in& guestDest, const uint8_t* data, size_t size,
                  std::vector<uint8_t>& wrapped, sockaddr_in& nativeDest);

// UDP receive: a datagram from the relay is unwrapped in place. On true,
// `datagram` holds just the payload and `guestSource` the address the guest
// should see it from.
bool UnwrapDatagram(const sockaddr_in& nativeSource, std::vector<uint8_t>& datagram,
                    sockaddr_in& guestSource);

// Extra bytes UnwrapDatagram may strip, for sizing receive buffers.
inline constexpr size_t kDatagramHeaderSize = 24;

}  // namespace NetworkHle::DirectOnline
