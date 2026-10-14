#pragma once

// Internals of the built-in WFC server and relay (direct-connect online).
// Everything here runs on the direct-mode thread, never on the emulation
// thread, so protocol handlers need no locking among themselves.

#include "direct_online.h"

#include <functional>
#include <map>

namespace NetworkHle::DirectOnline {

// Logs a payload as escaped text, truncated, for protocol bring-up.
void LogPayload(const char* label, const uint8_t* data, size_t size);

// Dotted IPv4 text of an address (no port).
std::string FormatAddress(const sockaddr_in& address);

// "a.b.c.d:port".
inline std::string FormatEndpoint(const sockaddr_in& address) {
    return FormatAddress(address) + ":" + std::to_string(ntohs(address.sin_port));
}

// Relay wire format (all integers big-endian):
// - Hello, client -> relay, on its own TCP connection before any game traffic
//   (kHelloSize = 21 bytes): "WCH1", clientId u64, build fingerprint u64,
//   product u8. The relay answers (kHelloReplySize = 14 bytes) "WCH1",
//   accepted u8, its own fingerprint u64 and product u8, then the players
//   logged in to it (count u8, at most 30, then a profile id u32 each), and
//   closes. A client repeats the hello to refresh that list.
// - TCP preamble, client -> relay, once per connection (35 bytes):
//     "WCT2", clientId u64, service port u16, stored user id u64,
//     stored profile id u32, build fingerprint u64, product u8
// - UDP header, both directions (kDatagramHeaderSize = 24 bytes):
//     "WCU1", clientId u64 (0 from the relay), source ip u32, source port u16,
//     destination ip u32, destination port u16
//   A client leaves the source ip 0: the relay knows its virtual IP.
// The relay serves only clients whose build matches its own: a hello or
// preamble with another fingerprint is refused, and datagrams are dropped
// until the client has passed one of them.
inline constexpr std::array<uint8_t, 4> kHelloMagic = {'W', 'C', 'H', '1'};
inline constexpr std::array<uint8_t, 4> kTcpMagic = {'W', 'C', 'T', '2'};
inline constexpr std::array<uint8_t, 4> kUdpMagic = {'W', 'C', 'U', '1'};
inline constexpr size_t kHelloSize = 21;
inline constexpr size_t kHelloReplySize = 14;
inline constexpr size_t kTcpPreambleSize = 35;

// Which build this runtime is: the first 8 bytes of the executable's SHA-256,
// so only byte-identical builds play together (a different build or pack can
// desync a race), plus the product, for the refusal message.
struct BuildId {
    uint64_t fingerprint = 0;
    uint8_t product = 0;  // RuntimeProduct::Kind

    bool operator==(const BuildId& other) const {
        return fingerprint == other.fingerprint && product == other.product;
    }
    bool operator!=(const BuildId& other) const { return !(*this == other); }
    // e.g. "Retro Rewind build 1a2b3c4d".
    std::string Describe() const;
};

// Hashes the executable on first use (a fraction of a second); call it from
// the direct-mode thread.
const BuildId& LocalBuild();

// 10.77.0.0/16, host byte order: the virtual IPs the relay assigns players.
inline constexpr uint32_t kVirtualNetwork = 0x0A4D0000u;

inline bool IsVirtualIp(uint32_t ip) {
    return (ip & 0xFFFF0000u) == kVirtualNetwork;
}

inline int SendFlags() {
#if defined(_WIN32) || defined(__APPLE__)
    return 0;
#else
    return MSG_NOSIGNAL;
#endif
}

// Big-endian field helpers for the relay wire format.
inline void PutU16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

inline void PutU32(std::vector<uint8_t>& out, uint32_t value) {
    PutU16(out, static_cast<uint16_t>(value >> 16));
    PutU16(out, static_cast<uint16_t>(value));
}

inline void PutU64(std::vector<uint8_t>& out, uint64_t value) {
    PutU32(out, static_cast<uint32_t>(value >> 32));
    PutU32(out, static_cast<uint32_t>(value));
}

inline uint16_t GetU16(const uint8_t* data) {
    return static_cast<uint16_t>((data[0] << 8) | data[1]);
}

inline uint32_t GetU32(const uint8_t* data) {
    return (static_cast<uint32_t>(GetU16(data)) << 16) | GetU16(data + 2);
}

inline uint64_t GetU64(const uint8_t* data) {
    return (static_cast<uint64_t>(GetU32(data)) << 32) | GetU32(data + 4);
}

// select() over a changing set of sockets, rebuilt every loop iteration.
class SocketSet {
public:
    void Clear();
    void Watch(NativeSocket socket);
    void Wait(int timeoutMs);
    bool IsReady(NativeSocket socket) const;

private:
    fd_set watched_{};
    fd_set ready_{};
    NativeSocket highest_ = 0;
};

// direct_relay.cpp: the host's relay and the built-in server behind it.
// `publicBind` listens on every interface (hosting); otherwise only loopback
// (playing alone). Port 0 picks one. TCP and UDP share the port.
bool StartRelay(bool publicBind, uint16_t port, uint16_t& boundPort);
// Lets `clientId` past the build check: the host's own runtime is the same
// build by definition.
void ApproveClient(uint64_t clientId);
void RelayWatch(SocketSet& sockets);
void RelayPump(const SocketSet& sockets);

// One TCP connection the server is handling, as seen by its protocol handler.
class TcpLink {
public:
    virtual ~TcpLink() = default;
    virtual void Send(const void* data, size_t size) = 0;
    void Send(std::string_view text) { Send(text.data(), text.size()); }
    // Closes after pending output; the handler gets no further data.
    virtual void Close() = 0;
    virtual const std::string& Label() const = 0;
    // The client's virtual address (its virtual IP; port 0).
    virtual const sockaddr_in& Peer() const = 0;
    // The GameSpy profile id the client's save already holds for `userId`, as
    // its runtime reported it when connecting.
    virtual std::optional<uint32_t> StoredProfileId(uint64_t userId) const = 0;
};

class TcpSession {
public:
    virtual ~TcpSession() = default;
    virtual void OnOpen(TcpLink&) {}
    // `buffer` holds every byte received and not yet consumed; a handler erases
    // what it has parsed and leaves an incomplete message in place.
    virtual void OnData(TcpLink& link, std::vector<uint8_t>& buffer) = 0;
    // Called on every server loop iteration (at least every 100 ms).
    virtual void OnTick(TcpLink&) {}
};

// Sends a datagram back to the sender of the one being handled.
using Reply = std::function<void(const void* data, size_t size)>;

// Sends a datagram to a client's game socket (`to` is its virtual address), as
// if from the server's UDP service on `servicePort`.
void SendToClient(const sockaddr_in& to, uint16_t servicePort, const void* data, size_t size);

// direct_nas.cpp: HTTP on 80/443 (NAS auth, conntest, sake).
std::unique_ptr<TcpSession> CreateHttpSession();

// direct_gpcm.cpp: GameSpy presence on 29900 (login, status, profiles) and
// profile search on 29901.
std::unique_ptr<TcpSession> CreateGpcmSession();
std::unique_ptr<TcpSession> CreateGpspSession();

// direct_qr2.cpp: UDP 27900 (available, heartbeats, keepalives, and the
// client messages the server browser relays).
void HandleQr2Packet(const sockaddr_in& from, const uint8_t* data, size_t size, const Reply& reply);
// Delivers a match command or NAT negotiation cookie to the QR2 session at
// `to`, resending until the client acknowledges it.
void SendQr2ClientMessage(const sockaddr_in& to, const uint8_t* message, size_t size);
// Called on every server loop iteration: message resends.
void Qr2Tick();

// direct_natneg.cpp: UDP 27901, NAT negotiation between joining players.
void HandleNatnegPacket(const sockaddr_in& from, const uint8_t* data, size_t size);
// Called on every server loop iteration: CONNECT resends and session expiry.
void NatnegTick();

// A friend code (DWC friend key): checksum << 32 | profile id. `gameId` is
// the 4-character game id ("RMCJ").
uint64_t FriendKey(uint32_t profileId, std::string_view gameId);
// Profile ids of everyone logged in to this server's GPCM.
std::vector<uint32_t> OnlineProfileIds();
// The profile a GPCM login ticket was issued to (sake identifies the player
// by it).
std::optional<uint32_t> ProfileForLoginTicket(const std::string& loginTicket);

// The players on the host this runtime plays through, by profile id: kept by
// the host's own GPCM, or reported to a client in the host's hello reply.
// Thread-safe.
void SetKnownPlayers(std::vector<uint32_t> profileIds);
std::vector<uint32_t> KnownPlayers();
// Bumped by every SetKnownPlayers that changes the list.
uint64_t KnownPlayersGeneration();

// direct_friends.cpp: adds KnownPlayers() to the current license's friend
// list. Emulation thread only: before the game logs in to GPCM, and from
// FriendListTick (direct_online.h) while online.
void AddKnownPlayersBeforeLogin();

// A registered QR2 session as the server browser lists it: the heartbeat's
// named keys, with publicip/publicport set to the client's virtual address.
using KeyValues = std::map<std::string, std::string>;
std::vector<KeyValues> Qr2Servers();

// GameSpy's publicip format: the IPv4 address as a big-endian int32, in signed
// decimal (common/ip_address.go).
std::string GameSpyIp(const sockaddr_in& address);

// direct_sb.cpp: server browser on TCP 28910.
std::unique_ptr<TcpSession> CreateServerBrowserSession();

// A NAS login, kept so GPCM can validate the auth token the client echoes back.
struct NasLogin {
    uint64_t userId = 0;
    uint64_t consoleFriendCode = 0;
    std::string gameCode;
    std::string gsbrCode;
    std::string challenge;
    std::vector<uint8_t> inGameName;  // raw UTF-16BE
};

void StoreNasLogin(const std::string& token, NasLogin login);
std::optional<NasLogin> FindNasLogin(const std::string& token);

// DWC's base64 variant: '+', '/', '=' become '.', '-', '*'.
std::string DwcBase64Encode(const uint8_t* data, size_t size);
std::optional<std::vector<uint8_t>> DwcBase64Decode(std::string_view text);

// The online identity the running game's DWC user data holds: its authentic
// user id and GameSpy profile id (0 if it has none). A save registered on
// another WFC server keeps that server's profile id and fails login (error
// 60000) if GPCM hands back a different one.
struct StoredIdentity {
    uint64_t userId = 0;
    uint32_t profileId = 0;
};
StoredIdentity ReadStoredIdentity();

uint64_t RandomU64();
std::string RandomUpper(size_t length);

}  // namespace NetworkHle::DirectOnline
