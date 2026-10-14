// The relay: the one port a host exposes. Every player's runtime (the host's
// own included, over loopback) sends its WFC traffic here. TCP connections are
// handed to the built-in server's protocol handlers; UDP datagrams go to the
// server's QR2 handler or on to another player. Players are known by virtual
// IPs (10.77.0.N) assigned on first contact. See direct_online.h.

#include "direct_server.h"

#include <map>
#include <set>

namespace NetworkHle::DirectOnline {

namespace {

NativeSocket g_tcp = kInvalidSocket;
NativeSocket g_udp = kInvalidSocket;

// Clients that passed the build check (a hello or a connection preamble).
std::set<uint64_t> g_approved;
// Clients whose datagrams were dropped for lacking one, logged once each.
std::set<uint64_t> g_unapprovedLogged;

// clientId -> virtual IP (host byte order).
std::map<uint64_t, uint32_t> g_virtualIps;
uint32_t g_nextHost = 2;

// (virtual IP, game socket port) -> the real address its datagrams come from.
std::map<uint64_t, sockaddr_in> g_endpoints;

uint64_t EndpointKey(uint32_t ip, uint16_t port) {
    return (static_cast<uint64_t>(ip) << 16) | port;
}

uint64_t EndpointKey(const sockaddr_in& address) {
    return EndpointKey(ntohl(address.sin_addr.s_addr), ntohs(address.sin_port));
}

sockaddr_in MakeAddress(uint32_t ip, uint16_t port) {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(ip);
    address.sin_port = htons(port);
    return address;
}

uint32_t VirtualIpFor(uint64_t clientId, const sockaddr_in& from) {
    const auto it = g_virtualIps.find(clientId);
    if (it != g_virtualIps.end()) {
        return it->second;
    }
    const uint32_t ip = kVirtualNetwork | g_nextHost++;
    g_virtualIps.emplace(clientId, ip);
    Log("relay: player %s joined from %s", FormatAddress(MakeAddress(ip, 0)).c_str(), FormatEndpoint(from).c_str());
    return ip;
}

// Relay -> client datagram to the game socket at virtual address `to`.
void SendWrapped(const sockaddr_in& to, const sockaddr_in& from, const void* data, size_t size) {
    const auto endpoint = g_endpoints.find(EndpointKey(to));
    if (endpoint == g_endpoints.end()) {
        Log("relay: no route to %s, dropping %zu bytes", FormatEndpoint(to).c_str(), size);
        return;
    }
    std::vector<uint8_t> packet(kUdpMagic.begin(), kUdpMagic.end());
    packet.insert(packet.end(), 8, 0);  // clientId 0: from the relay
    PutU32(packet, ntohl(from.sin_addr.s_addr));
    PutU16(packet, ntohs(from.sin_port));
    PutU32(packet, ntohl(to.sin_addr.s_addr));
    PutU16(packet, ntohs(to.sin_port));
    const auto* bytes = static_cast<const uint8_t*>(data);
    packet.insert(packet.end(), bytes, bytes + size);
    ::sendto(g_udp, reinterpret_cast<const char*>(packet.data()), static_cast<int>(packet.size()), 0,
             reinterpret_cast<const sockaddr*>(&endpoint->second), sizeof(endpoint->second));
}

class LoggingSession final : public TcpSession {
public:
    explicit LoggingSession(uint16_t port) : port_(port) {}
    void OnData(TcpLink& link, std::vector<uint8_t>& buffer) override {
        const std::string label = link.Label() + " port " + std::to_string(port_) + " (unhandled)";
        LogPayload(label.c_str(), buffer.data(), buffer.size());
        buffer.clear();
    }

private:
    uint16_t port_;
};

const char* ServiceName(uint16_t port) {
    switch (port) {
    case 80: return "http";
    case 443: return "https";
    case 29900: return "gpcm";
    case 29901: return "gpsp";
    case 28910: return "sb";
    default: return "tcp";
    }
}

std::unique_ptr<TcpSession> CreateSession(uint16_t port) {
    switch (port) {
    case 80:
    case 443: return CreateHttpSession();
    case 29900: return CreateGpcmSession();
    case 29901: return CreateGpspSession();
    case 28910: return CreateServerBrowserSession();
    default: return std::make_unique<LoggingSession>(port);
    }
}

// A relay TCP connection. Until its preamble has arrived it only buffers;
// afterwards it is the server's link to one client service connection.
class RelayConnection final : public TcpLink {
public:
    RelayConnection(NativeSocket socket, sockaddr_in from, uint64_t id)
        : socket_(socket), from_(from), label_("relay#" + std::to_string(id)) {}
    ~RelayConnection() override { CloseNativeSocket(socket_); }

    void Send(const void* data, size_t size) override {
        const auto* bytes = static_cast<const char*>(data);
        size_t offset = 0;
        while (offset < size && !closing_) {
            const int chunk = static_cast<int>(std::min<size_t>(size - offset, 64 * 1024));
            const int sent = ::send(socket_, bytes + offset, chunk, SendFlags());
            if (sent <= 0) {
                Log("%s send failed (error %d), closing", label_.c_str(), NativeLastError());
                closing_ = true;
                break;
            }
            offset += static_cast<size_t>(sent);
        }
    }

    void Close() override { closing_ = true; }
    const std::string& Label() const override { return label_; }
    const sockaddr_in& Peer() const override { return peer_; }

    std::optional<uint32_t> StoredProfileId(uint64_t userId) const override {
        if (storedProfileId_ == 0 || storedUserId_ != userId) {
            return std::nullopt;
        }
        return storedProfileId_;
    }

    NativeSocket Socket() const { return socket_; }
    bool Closing() const { return closing_; }

    void Tick() {
        if (session_ && !closing_) {
            session_->OnTick(*this);
        }
    }

    // Returns false once the connection should be dropped.
    bool Pump() {
        std::array<char, 16 * 1024> chunk{};
        const int received = ::recv(socket_, chunk.data(), static_cast<int>(chunk.size()), 0);
        if (received <= 0) {
            return false;
        }
        buffer_.insert(buffer_.end(), chunk.begin(), chunk.begin() + received);
        if (!session_ && !ReadPreamble()) {
            return !closing_;
        }
        if (session_ && !buffer_.empty()) {
            session_->OnData(*this, buffer_);
        }
        return !closing_;
    }

private:
    // Answers a build-check hello: the reply carries our build either way, so
    // a refused client can say what the host runs.
    void AnswerHello() {
        const uint64_t clientId = GetU64(buffer_.data() + 4);
        const BuildId theirs{GetU64(buffer_.data() + 12), buffer_[20]};
        const BuildId& ours = LocalBuild();
        const bool accepted = theirs == ours;
        if (accepted) {
            // Clients repeat the hello to refresh the player list; log once.
            if (g_approved.insert(clientId).second) {
                Log("relay: build check passed for %s (%s)", FormatEndpoint(from_).c_str(), theirs.Describe().c_str());
            }
        } else {
            Log("relay: refused %s: it runs %s, this host runs %s", FormatEndpoint(from_).c_str(),
                theirs.Describe().c_str(), ours.Describe().c_str());
        }
        std::vector<uint8_t> reply(kHelloMagic.begin(), kHelloMagic.end());
        reply.push_back(accepted ? 1 : 0);
        PutU64(reply, ours.fingerprint);
        reply.push_back(ours.product);
        std::vector<uint32_t> players = accepted ? OnlineProfileIds() : std::vector<uint32_t>{};
        if (players.size() > 30) {
            players.resize(30);
        }
        reply.push_back(static_cast<uint8_t>(players.size()));
        for (const uint32_t profileId : players) {
            PutU32(reply, profileId);
        }
        Send(reply.data(), reply.size());
        closing_ = true;
    }

    // Returns true once the session exists.
    bool ReadPreamble() {
        if (buffer_.size() >= 4 && std::equal(kHelloMagic.begin(), kHelloMagic.end(), buffer_.begin())) {
            if (buffer_.size() >= kHelloSize) {
                AnswerHello();
            }
            return false;
        }
        if (buffer_.size() >= 4 && !std::equal(kTcpMagic.begin(), kTcpMagic.end(), buffer_.begin())) {
            // "WCT1" was the preamble before build checks existed.
            const bool olderBuild = std::equal(kTcpMagic.begin(), kTcpMagic.end() - 1, buffer_.begin());
            Log("%s from %s is %s, closing", label_.c_str(), FormatEndpoint(from_).c_str(),
                olderBuild ? "an older direct-online build" : "not a direct-online client");
            closing_ = true;
            return false;
        }
        if (buffer_.size() < kTcpPreambleSize) {
            return false;
        }
        const uint64_t clientId = GetU64(buffer_.data() + 4);
        const uint16_t port = GetU16(buffer_.data() + 12);
        storedUserId_ = GetU64(buffer_.data() + 14);
        storedProfileId_ = GetU32(buffer_.data() + 22);
        const BuildId theirs{GetU64(buffer_.data() + 26), buffer_[34]};
        buffer_.erase(buffer_.begin(), buffer_.begin() + kTcpPreambleSize);
        if (theirs != LocalBuild()) {
            Log("%s from %s refused: it runs %s, this host runs %s", label_.c_str(), FormatEndpoint(from_).c_str(),
                theirs.Describe().c_str(), LocalBuild().Describe().c_str());
            closing_ = true;
            return false;
        }
        g_approved.insert(clientId);

        const uint32_t ip = VirtualIpFor(clientId, from_);
        peer_ = MakeAddress(ip, 0);
        label_ = std::string(ServiceName(port)) + label_.substr(label_.find('#')) + " [" + FormatAddress(peer_) + "]";
        Log("%s connected", label_.c_str());
        session_ = CreateSession(port);
        session_->OnOpen(*this);
        return true;
    }

    NativeSocket socket_;
    sockaddr_in from_;
    sockaddr_in peer_{};
    std::string label_;
    std::unique_ptr<TcpSession> session_;
    std::vector<uint8_t> buffer_;
    uint64_t storedUserId_ = 0;
    uint32_t storedProfileId_ = 0;
    bool closing_ = false;
};

std::vector<std::unique_ptr<RelayConnection>> g_connections;
uint64_t g_nextConnectionId = 1;

void HandleDatagram() {
    std::array<uint8_t, 4096> buffer{};
    sockaddr_in from{};
    socklen_t fromLength = sizeof(from);
    const int received = ::recvfrom(g_udp, reinterpret_cast<char*>(buffer.data()),
                                    static_cast<int>(buffer.size()), 0,
                                    reinterpret_cast<sockaddr*>(&from), &fromLength);
    if (received < static_cast<int>(kDatagramHeaderSize) ||
        !std::equal(kUdpMagic.begin(), kUdpMagic.end(), buffer.begin())) {
        return;
    }
    const uint64_t clientId = GetU64(buffer.data() + 4);
    if (clientId == 0) {
        return;
    }
    if (!g_approved.count(clientId)) {
        if (g_unapprovedLogged.insert(clientId).second) {
            Log("relay: dropping datagrams from %s until it passes the build check", FormatEndpoint(from).c_str());
        }
        return;
    }
    const uint32_t ip = VirtualIpFor(clientId, from);
    const sockaddr_in source = MakeAddress(ip, GetU16(buffer.data() + 16));
    const sockaddr_in destination = MakeAddress(GetU32(buffer.data() + 18), GetU16(buffer.data() + 22));
    g_endpoints[EndpointKey(source)] = from;

    const uint8_t* payload = buffer.data() + kDatagramHeaderSize;
    const size_t size = static_cast<size_t>(received) - kDatagramHeaderSize;
    const uint32_t destinationIp = ntohl(destination.sin_addr.s_addr);

    if (destinationIp == kPlaceholderIp) {
        const uint16_t service = ntohs(destination.sin_port);
        if (service == 27900) {
            HandleQr2Packet(source, payload, size, [&](const void* reply, size_t replySize) {
                SendToClient(source, 27900, reply, replySize);
            });
        } else if (service == 27901) {
            HandleNatnegPacket(source, payload, size);
        } else {
            LogPayload(("udp port " + std::to_string(service) + " from " + FormatEndpoint(source) + " (unhandled)").c_str(),
                       payload, size);
        }
        return;
    }
    if (IsVirtualIp(destinationIp)) {
        // NAT negotiation pings between players (NATNEG magic, command at 7):
        // logged to time the negotiation.
        static constexpr std::array<uint8_t, 6> kNatnegMagic = {0xFD, 0xFC, 0x1E, 0x66, 0x6A, 0xB2};
        if (size >= 8 && std::equal(kNatnegMagic.begin(), kNatnegMagic.end(), payload)) {
            Log("relay: natneg 0x%02X %s -> %s", payload[7], FormatEndpoint(source).c_str(),
                FormatEndpoint(destination).c_str());
        }
        SendWrapped(destination, source, payload, size);
        return;
    }
    Log("relay: %s sent to non-virtual %s, dropped", FormatEndpoint(source).c_str(), FormatEndpoint(destination).c_str());
}

}  // namespace

void SendToClient(const sockaddr_in& to, uint16_t servicePort, const void* data, size_t size) {
    SendWrapped(to, MakeAddress(kPlaceholderIp, servicePort), data, size);
}

void ApproveClient(uint64_t clientId) {
    g_approved.insert(clientId);
}

bool StartRelay(bool publicBind, uint16_t port, uint16_t& boundPort) {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(publicBind ? INADDR_ANY : INADDR_LOOPBACK);
    address.sin_port = htons(port);

    g_tcp = ::socket(AF_INET, SOCK_STREAM, 0);
    if (g_tcp == kInvalidSocket) {
        Log("relay: could not create a TCP socket (error %d)", NativeLastError());
        return false;
    }
    if (::bind(g_tcp, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        const int error = NativeLastError();
        // A host restarted within a couple of minutes finds its port still
        // held by its last session's closed connections (TIME_WAIT: the
        // server closes every HTTP connection), and a plain bind fails. If
        // nothing is actually listening there, bind again allowing reuse;
        // a real second host on the port still fails.
        sockaddr_in probe = address;
        probe.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        const NativeSocket probeSocket = ::socket(AF_INET, SOCK_STREAM, 0);
        const bool someoneListening = probeSocket != kInvalidSocket &&
            ::connect(probeSocket, reinterpret_cast<const sockaddr*>(&probe), sizeof(probe)) == 0;
        if (probeSocket != kInvalidSocket) CloseNativeSocket(probeSocket);
        const int reuse = 1;
        if (port == 0 || someoneListening ||
            ::setsockopt(g_tcp, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse)) != 0 ||
            ::bind(g_tcp, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
            Log("relay: could not listen on TCP port %u (error %d)%s", port, error,
                someoneListening ? ": another program (another host?) is already using it" : "");
            return false;
        }
        Log("relay: port %u was still held by closed connections; reusing it", port);
    }
    socklen_t length = sizeof(address);
    if (::listen(g_tcp, 32) != 0 || ::getsockname(g_tcp, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
        Log("relay: could not listen on TCP port %u (error %d)", port, NativeLastError());
        return false;
    }
    // UDP on the same port number, so a host forwards just one port.
    g_udp = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (g_udp == kInvalidSocket || ::bind(g_udp, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        Log("relay: could not bind UDP port %u (error %d)", ntohs(address.sin_port), NativeLastError());
        return false;
    }
#ifdef _WIN32
    // A client that went away makes Windows report WSAECONNRESET on the next
    // recvfrom; that must not look like an error on the shared relay socket.
    BOOL reportReset = FALSE;
    DWORD bytes = 0;
    WSAIoctl(g_udp, SIO_UDP_CONNRESET, &reportReset, sizeof(reportReset), nullptr, 0, &bytes, nullptr, nullptr);
#endif
    boundPort = ntohs(address.sin_port);
    Log("relay: listening on %s port %u (TCP and UDP)", publicBind ? "all interfaces" : "loopback", boundPort);
    return true;
}

void RelayWatch(SocketSet& sockets) {
    sockets.Watch(g_tcp);
    sockets.Watch(g_udp);
    for (const auto& connection : g_connections) {
        sockets.Watch(connection->Socket());
    }
}

void RelayPump(const SocketSet& sockets) {
    if (sockets.IsReady(g_tcp)) {
        sockaddr_in from{};
        socklen_t length = sizeof(from);
        const NativeSocket accepted = ::accept(g_tcp, reinterpret_cast<sockaddr*>(&from), &length);
        if (accepted != kInvalidSocket) {
#ifdef __APPLE__
            const int on = 1;
            setsockopt(accepted, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
            g_connections.push_back(std::make_unique<RelayConnection>(accepted, from, g_nextConnectionId++));
        }
    }
    if (sockets.IsReady(g_udp)) {
        HandleDatagram();
    }
    for (auto it = g_connections.begin(); it != g_connections.end();) {
        RelayConnection& connection = **it;
        const bool keep = !connection.Closing() &&
            (!sockets.IsReady(connection.Socket()) || connection.Pump());
        if (keep) {
            connection.Tick();
        }
        if (keep) {
            ++it;
        } else {
            Log("%s closed", connection.Label().c_str());
            it = g_connections.erase(it);
        }
    }
}

}  // namespace NetworkHle::DirectOnline
