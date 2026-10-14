// NAT negotiation (GameSpy NATNEG, UDP 27901) side of the built-in WFC server.
// When players join each other, each one INITs a session (keyed by a cookie
// they exchanged as a match command) from its game socket and its negotiation
// socket; once both are known the server sends each a CONNECT naming the
// other's game socket, and they ping each other directly. Every address here
// is a virtual relay address, so the "direct" pings already go through the
// relay. Protocol reference: WiiLink wfc-server, natneg/.

#include "direct_server.h"

#include <chrono>
#include <map>

namespace NetworkHle::DirectOnline {

namespace {

using Clock = std::chrono::steady_clock;

enum NatnegCommand : uint8_t {
    kNnInit = 0x00,
    kNnInitReply = 0x01,
    kNnConnect = 0x05,
    kNnConnectReply = 0x06,
    kNnReport = 0x0D,
    kNnReportReply = 0x0E,
    kNnPreInit = 0x0F,
    kNnPreInitReply = 0x10,
};

constexpr std::array<uint8_t, 6> kNatnegMagic = {0xFD, 0xFC, 0x1E, 0x66, 0x6A, 0xB2};
constexpr uint8_t kPortTypeGame = 0x00;
constexpr uint8_t kPreInitReady = 0x02;

struct NnClient {
    uint8_t index = 0;
    // The client this one is currently being connected to; its own index
    // while idle.
    uint8_t connectingIndex = 0;
    bool connectAck = false;
    Clock::time_point nextConnect{};
    // Connection results this client reported, by peer index.
    std::map<uint8_t, uint8_t> results;
    std::optional<sockaddr_in> negotiate;  // where CONNECTs go
    std::optional<sockaddr_in> server;     // its game socket, handed to peers
    std::string gameName;

    bool Mapped() const { return negotiate && server; }
};

struct NnSession {
    uint8_t version = 0;
    uint32_t cookie = 0;
    Clock::time_point expires{};
    std::map<uint8_t, NnClient> clients;
};

std::map<uint32_t, NnSession> g_natneg;

std::vector<uint8_t> NatnegHeader(uint8_t version, uint8_t command, uint32_t cookie) {
    std::vector<uint8_t> packet(kNatnegMagic.begin(), kNatnegMagic.end());
    packet.push_back(version);
    packet.push_back(command);
    PutU32(packet, cookie);
    return packet;
}

void Send(const sockaddr_in& to, const std::vector<uint8_t>& packet) {
    SendToClient(to, 27901, packet.data(), packet.size());
}

// natneg/connect.go sendConnectRequests: pair every idle mapped client with
// every other idle mapped client it has no result for yet.
void PairClients(NnSession& session) {
    for (auto& [id, sender] : session.clients) {
        if (!sender.Mapped() || sender.connectingIndex != id) continue;
        for (auto& [destinationId, destination] : session.clients) {
            if (id == destinationId || !destination.Mapped() || destination.connectingIndex != destinationId ||
                destination.results.count(id)) {
                continue;
            }
            sender.connectingIndex = destinationId;
            sender.connectAck = false;
            sender.nextConnect = Clock::now();
            destination.connectingIndex = id;
            destination.connectAck = false;
            destination.nextConnect = Clock::now();
            Log("natneg %08X: connecting client %u (%s) and client %u (%s)", session.cookie, id,
                FormatEndpoint(*sender.server).c_str(), destinationId, FormatEndpoint(*destination.server).c_str());
            break;
        }
    }
}

void Init(NnSession& session, const sockaddr_in& from, const uint8_t* body, size_t size) {
    if (size < 10) return;
    const uint8_t portType = body[0];
    const uint8_t clientIndex = body[1];
    const uint8_t useGamePort = body[2];
    const auto* nameBegin = reinterpret_cast<const char*>(body + 9);
    const std::string gameName(nameBegin, strnlen(nameBegin, size - 9));
    if (portType > 0x03 || useGamePort > 1 || (useGamePort == 0 && portType == kPortTypeGame)) return;

    std::vector<uint8_t> ack = NatnegHeader(session.version, kNnInitReply, session.cookie);
    ack.insert(ack.end(), {portType, clientIndex, 0xFF, 0xFF, 0x6D, 0x16, 0xB5, 0x7D, 0xEA});
    Send(from, ack);

    auto it = session.clients.find(clientIndex);
    if (it == session.clients.end()) {
        for (const auto& [id, other] : session.clients) {
            if (other.gameName != gameName) return;
        }
        NnClient client;
        client.index = clientIndex;
        client.connectingIndex = clientIndex;
        it = session.clients.emplace(clientIndex, std::move(client)).first;
    }
    NnClient& client = it->second;
    client.gameName = gameName;
    if (portType != kPortTypeGame) client.negotiate = from;
    if (useGamePort == 0 || portType == kPortTypeGame) client.server = from;
    if (client.Mapped()) PairClients(session);
}

void Report(NnSession& session, const sockaddr_in& from, const uint8_t* body, size_t size) {
    if (size < 9) return;
    std::vector<uint8_t> reply = NatnegHeader(session.version, kNnReportReply, session.cookie);
    reply.insert(reply.end(), body, body + 9);
    reply[14] = 0;
    Send(from, reply);

    const uint8_t clientIndex = body[1];
    const uint8_t result = body[2];
    const auto it = session.clients.find(clientIndex);
    if (it == session.clients.end()) return;
    NnClient& client = it->second;
    Log("natneg %08X: client %u reports result %u for client %u", session.cookie, clientIndex, result,
        client.connectingIndex);
    client.results[client.connectingIndex] = result;
    client.connectingIndex = clientIndex;
    client.connectAck = false;
    PairClients(session);
}

}  // namespace

void HandleNatnegPacket(const sockaddr_in& from, const uint8_t* data, size_t size) {
    if (size < 12 || !std::equal(kNatnegMagic.begin(), kNatnegMagic.end(), data)) return;
    const uint8_t version = data[6];
    const uint8_t command = data[7];
    const uint32_t cookie = GetU32(data + 8);
    const uint8_t* body = data + 12;
    const size_t bodySize = size - 12;

    auto it = g_natneg.find(cookie);
    if (it == g_natneg.end()) {
        NnSession session;
        session.version = version;
        session.cookie = cookie;
        session.expires = Clock::now() + std::chrono::seconds(30);
        it = g_natneg.emplace(cookie, std::move(session)).first;
    }
    NnSession& session = it->second;
    if (session.version != version) return;
    Log("natneg %08X: command 0x%02X from %s (%zu bytes)%s", cookie, command, FormatEndpoint(from).c_str(), size,
        bodySize >= 2 ? (" port type " + std::to_string(body[0]) + " client " + std::to_string(body[1])).c_str() : "");

    switch (command) {
    case kNnInit:
        Init(session, from, body, bodySize);
        break;
    case kNnConnectReply:
        if (bodySize >= 2) {
            const auto client = session.clients.find(body[1]);
            if (client != session.clients.end()) client->second.connectAck = true;
        }
        break;
    case kNnReport:
        Report(session, from, body, bodySize);
        break;
    case kNnPreInit:
        if (bodySize >= 6) {
            std::vector<uint8_t> reply = NatnegHeader(version, kNnPreInitReply, cookie);
            reply.insert(reply.end(), body, body + 6);
            reply[13] = kPreInitReady;
            Send(from, reply);
        }
        break;
    default:
        break;
    }
}

void NatnegTick() {
    const auto now = Clock::now();
    for (auto it = g_natneg.begin(); it != g_natneg.end();) {
        NnSession& session = it->second;
        if (now >= session.expires) {
            // natneg/main.go closeSession: anyone still mid-connection is told
            // it failed.
            for (const auto& [id, client] : session.clients) {
                if (client.connectingIndex == client.index || !client.negotiate) continue;
                std::vector<uint8_t> failed = NatnegHeader(session.version, kNnReportReply, session.cookie);
                failed.insert(failed.end(), {0x00, client.index, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00});
                Send(*client.negotiate, failed);
            }
            it = g_natneg.erase(it);
            continue;
        }
        for (auto& [id, client] : session.clients) {
            if (client.connectingIndex == client.index || client.connectAck || now < client.nextConnect) continue;
            const auto peer = session.clients.find(client.connectingIndex);
            if (peer == session.clients.end() || !peer->second.server || !client.negotiate) continue;
            // CONNECT: the peer's game socket address, then 0x42 0x00.
            std::vector<uint8_t> connect = NatnegHeader(session.version, kNnConnect, session.cookie);
            PutU32(connect, ntohl(peer->second.server->sin_addr.s_addr));
            PutU16(connect, ntohs(peer->second.server->sin_port));
            connect.insert(connect.end(), {0x42, 0x00});
            Send(*client.negotiate, connect);
            client.nextConnect = now + std::chrono::milliseconds(500);
        }
        ++it;
    }
}

}  // namespace NetworkHle::DirectOnline
