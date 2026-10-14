// QR2 (GameSpy query/reporting, UDP 27900) side of the built-in WFC server:
// the available check, heartbeat registration through the challenge
// handshake, and keepalives. Registered sessions are what the server browser
// lists. Protocol reference: WiiLink wfc-server, qr2/main.go,
// qr2/heartbeat.go and qr2/challenge.go.

#include "direct_server.h"

#include <chrono>
#include <map>

namespace NetworkHle::DirectOnline {

namespace {

enum Qr2Packet : uint8_t {
    kQuery = 0x00,
    kChallenge = 0x01,
    kEcho = 0x02,
    kHeartbeat = 0x03,
    kAddError = 0x04,
    kEchoResponse = 0x05,
    kClientMessage = 0x06,
    kClientMessageAck = 0x07,
    kKeepAlive = 0x08,
    kAvailable = 0x09,
    kClientRegistered = 0x0A,
};

struct PendingMessage {
    std::vector<uint8_t> packet;
    std::chrono::steady_clock::time_point nextSend;
    int sends = 0;
};

struct Qr2Session {
    sockaddr_in address{};
    uint32_t sessionId = 0;
    uint32_t messageCounter = 0;
    // Client messages awaiting an ack (0x07), resent once a second.
    std::vector<PendingMessage> pending;
    std::string challenge;
    bool authenticated = false;
    // Heartbeat keys in arrival order. GameSpy reports the game's custom keys
    // (dwc_pid, dwc_mtype, ...) under the name "unknown", so a map would lose them.
    std::vector<std::pair<std::string, std::string>> keys;
    std::chrono::steady_clock::time_point lastSeen;
};

std::map<std::string, Qr2Session> g_sessions;

std::string AddressKey(const sockaddr_in& address) {
    char text[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &address.sin_addr, text, sizeof(text));
    return std::string(text) + ":" + std::to_string(ntohs(address.sin_port));
}

std::vector<uint8_t> Header(uint8_t type, uint32_t sessionId) {
    return {0xFE, 0xFD, type, static_cast<uint8_t>(sessionId >> 24),
            static_cast<uint8_t>(sessionId >> 16), static_cast<uint8_t>(sessionId >> 8),
            static_cast<uint8_t>(sessionId)};
}

uint32_t ReadSessionId(const uint8_t* data) {
    return (static_cast<uint32_t>(data[1]) << 24) | (static_cast<uint32_t>(data[2]) << 16) |
        (static_cast<uint32_t>(data[3]) << 8) | data[4];
}

// NUL-separated key\0value\0 pairs after the 5-byte header, ended by an empty key.
std::vector<std::pair<std::string, std::string>> ParseHeartbeat(const uint8_t* data, size_t size) {
    std::vector<std::pair<std::string, std::string>> keys;
    size_t offset = 5;
    auto readString = [&](std::string& out) {
        const auto* begin = reinterpret_cast<const char*>(data + offset);
        const auto* nul = static_cast<const char*>(std::memchr(begin, 0, size - offset));
        if (!nul) return false;
        out.assign(begin, nul);
        offset += out.size() + 1;
        return true;
    };
    while (offset < size) {
        std::string key;
        std::string value;
        if (!readString(key) || key.empty() || !readString(value)) break;
        keys.emplace_back(std::move(key), std::move(value));
    }
    return keys;
}

std::string FindKey(const std::vector<std::pair<std::string, std::string>>& keys, std::string_view name) {
    for (const auto& [key, value] : keys) {
        if (key == name) return value;
    }
    return {};
}

// qr2/challenge.go: 6 random characters, "00", then the observed public IP and
// port in hex. The client reads its public address back out of it.
std::string MakeChallenge(const sockaddr_in& from) {
    const uint32_t ip = ntohl(from.sin_addr.s_addr);
    char tail[16];
    std::snprintf(tail, sizeof(tail), "00%02X%02X%02X%02X%04X", ip >> 24, (ip >> 16) & 0xFF,
                  (ip >> 8) & 0xFF, ip & 0xFF, ntohs(from.sin_port));
    return RandomUpper(6) + tail;
}

void SendChallenge(Qr2Session& session, const Reply& reply) {
    std::vector<uint8_t> packet = Header(kChallenge, session.sessionId);
    packet.insert(packet.end(), session.challenge.begin(), session.challenge.end());
    packet.push_back(0);
    reply(packet.data(), packet.size());
}

void Heartbeat(const sockaddr_in& from, const uint8_t* data, size_t size, const Reply& reply) {
    const std::string key = AddressKey(from);
    auto keys = ParseHeartbeat(data, size);
    const std::string stateChanged = FindKey(keys, "statechanged");
    if (stateChanged == "2") {
        g_sessions.erase(key);
        Log("qr2 %s: session closed", key.c_str());
        return;
    }

    const bool isNew = g_sessions.count(key) == 0;
    Qr2Session& session = g_sessions[key];
    session.address = from;
    session.sessionId = ReadSessionId(data);
    session.lastSeen = std::chrono::steady_clock::now();
    const std::string publicIp = FindKey(keys, "publicip");
    const bool noPublicIp = publicIp.empty() || publicIp == "0";
    session.keys = std::move(keys);

    if (isNew || stateChanged == "1") {
        std::string summary;
        for (const auto& [name, value] : session.keys) {
            summary += name + "=" + value + " ";
        }
        Log("qr2 %s: heartbeat statechanged=%s %s", key.c_str(), stateChanged.c_str(), summary.c_str());
    }

    // As wfc-server does: (re)challenge until the client has answered and
    // reports the public address the challenge told it.
    if (!session.authenticated || noPublicIp) {
        if (session.challenge.empty()) {
            session.challenge = MakeChallenge(from);
        }
        SendChallenge(session, reply);
    }
}

}  // namespace

std::string GameSpyIp(const sockaddr_in& address) {
    return std::to_string(static_cast<int32_t>(ntohl(address.sin_addr.s_addr)));
}

void SendQr2ClientMessage(const sockaddr_in& to, const uint8_t* message, size_t size) {
    const std::string key = AddressKey(to);
    const auto it = g_sessions.find(key);
    if (it == g_sessions.end()) {
        Log("qr2: client message for %s, which has no session; dropped", key.c_str());
        return;
    }
    Qr2Session& session = it->second;
    // qr2/message.go: FE FD 06, the receiver's session id, a big-endian
    // message counter, then the message itself.
    PendingMessage pending;
    pending.packet = Header(kClientMessage, session.sessionId);
    const uint32_t counter = ++session.messageCounter;
    for (int shift = 24; shift >= 0; shift -= 8) {
        pending.packet.push_back(static_cast<uint8_t>(counter >> shift));
    }
    pending.packet.insert(pending.packet.end(), message, message + size);
    pending.nextSend = std::chrono::steady_clock::now();
    LogPayload(("qr2 " + key + ": client message").c_str(), message, size);
    session.pending.push_back(std::move(pending));
    Qr2Tick();
}

void Qr2Tick() {
    constexpr int kMaxSends = 10;
    const auto now = std::chrono::steady_clock::now();
    for (auto& [key, session] : g_sessions) {
        for (auto it = session.pending.begin(); it != session.pending.end();) {
            if (now < it->nextSend) {
                ++it;
                continue;
            }
            if (it->sends >= kMaxSends) {
                Log("qr2 %s: client message never acknowledged, giving up", key.c_str());
                it = session.pending.erase(it);
                continue;
            }
            SendToClient(session.address, 27900, it->packet.data(), it->packet.size());
            ++it->sends;
            it->nextSend = now + std::chrono::seconds(1);
            ++it;
        }
    }
}

std::vector<KeyValues> Qr2Servers() {
    constexpr auto kStale = std::chrono::seconds(60);
    const auto now = std::chrono::steady_clock::now();
    std::vector<KeyValues> servers;
    for (const auto& [key, session] : g_sessions) {
        if (!session.authenticated || now - session.lastSeen > kStale) {
            continue;
        }
        KeyValues values;
        for (const auto& [name, value] : session.keys) {
            if (name != "unknown") {
                values[name] = value;
            }
        }
        values["publicip"] = GameSpyIp(session.address);
        values["publicport"] = std::to_string(ntohs(session.address.sin_port));
        servers.push_back(std::move(values));
    }
    return servers;
}

void HandleQr2Packet(const sockaddr_in& from, const uint8_t* data, size_t size, const Reply& reply) {
    if (size < 5) {
        return;
    }
    const uint8_t type = data[0];

    if (type == kAvailable) {
        const std::vector<uint8_t> packet = Header(kAvailable, 0);
        reply(packet.data(), packet.size());
        return;
    }
    if (type == kHeartbeat) {
        Heartbeat(from, data, size, reply);
        return;
    }

    const std::string key = AddressKey(from);
    const auto it = g_sessions.find(key);
    if (it == g_sessions.end()) {
        Log("qr2 %s: packet type %u without a session", key.c_str(), type);
        return;
    }
    Qr2Session& session = it->second;
    session.sessionId = ReadSessionId(data);
    session.lastSeen = std::chrono::steady_clock::now();

    switch (type) {
    case kChallenge:
        // wfc-server does not verify the response either.
        if (!session.challenge.empty()) {
            if (!session.authenticated) {
                Log("qr2 %s: registered (session %08X)", key.c_str(), session.sessionId);
            }
            session.authenticated = true;
            const std::vector<uint8_t> packet = Header(kClientRegistered, session.sessionId);
            reply(packet.data(), packet.size());
        }
        return;
    case kKeepAlive: {
        const std::vector<uint8_t> packet = Header(kKeepAlive, 0);
        reply(packet.data(), packet.size());
        return;
    }
    case kClientMessageAck:
        // wfc-server treats any ack as acknowledging everything outstanding.
        session.pending.clear();
        return;
    default:
        LogPayload(("qr2 " + key + " (unhandled)").c_str(), data, size);
        return;
    }
}

}  // namespace NetworkHle::DirectOnline
