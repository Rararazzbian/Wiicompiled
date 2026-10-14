// Server browser (GameSpy SB, TCP 28910) side of the built-in WFC server:
// server-list requests filtered over the registered QR2 sessions and answered
// with GameSpy's "enctype X" stream cipher. Protocol reference: WiiLink
// wfc-server, serverbrowser/main.go, serverbrowser/server.go,
// serverbrowser/filter.go, filter/ and common/encryption.go.

#include "direct_server.h"

#include <cctype>
#include <ctime>

namespace NetworkHle::DirectOnline {

namespace {

enum SbRequest : uint8_t {
    kServerList = 0x00,
    kServerInfo = 0x01,
    kSendMessage = 0x02,
    kKeepaliveReply = 0x03,
};

enum SbServerFlag : uint8_t {
    kPrivateIp = 0x02,
    kConnectNegotiate = 0x04,
    kIcmpIp = 0x08,
    kNonstandardPort = 0x10,
    kNonstandardPrivatePort = 0x20,
    kHasKeys = 0x40,
};

constexpr uint32_t kNoServerListOption = 0x02;

// mariokartwii's GameSpy secret key (wfc-server game_list.tsv).
constexpr std::string_view kSecretKey = "9r3Rmy";

// ---------------------------------------------------------------------------
// Enctype X, ported from common/encryption.go. Every intermediate is a byte
// in the original, so the uint8_t arithmetic here wraps exactly as Go's does.

struct EncTypeX {
    std::array<uint8_t, 261> key{};

    void Shuffle(const uint8_t* challenge, int challengeLength) {
        for (int i = 0; i < 256; ++i) key[i] = static_cast<uint8_t>(i);
        int n1 = 0;
        int n2 = 0;
        for (int i = 255; i >= 0; --i) {
            const int swapIndex = Pick(i, challenge, challengeLength, n1, n2);
            std::swap(key[i], key[swapIndex]);
        }
        key[256] = key[1];
        key[257] = key[3];
        key[258] = key[5];
        key[259] = key[7];
        key[260] = key[n1 & 0xFF];
    }

    // func5
    int Pick(int count, const uint8_t* id, int idLength, int& n1, int& n2) const {
        if (count == 0) return 0;
        int mask = 1;
        while (mask < count) mask = (mask << 1) + 1;
        int tmp = 0;
        for (int i = 1;; ++i) {
            n1 = static_cast<uint8_t>(key[n1 & 0xFF] + id[n2]);
            if (++n2 >= idLength) {
                n2 = 0;
                n1 += idLength;
            }
            tmp = n1 & mask;
            if (i > 11) tmp %= count;
            if (tmp <= count) return tmp;
        }
    }

    // func7e
    uint8_t Encrypt(uint8_t d) {
        uint8_t a = key[256];
        uint8_t b = key[257];
        uint8_t c = key[a];
        key[256] = static_cast<uint8_t>(a + 1);
        key[257] = static_cast<uint8_t>(b + c);

        a = key[260];
        b = key[257];
        b = key[b];
        c = key[a];
        key[a] = b;

        a = key[259];
        b = key[257];
        a = key[a];
        key[b] = a;

        a = key[256];
        b = key[259];
        a = key[a];
        key[b] = a;

        a = key[256];
        key[a] = c;

        b = key[258];
        a = key[c];
        c = key[259];
        b = static_cast<uint8_t>(a + b);
        key[258] = b;

        a = b;
        c = key[c];
        b = key[257];
        b = key[b];
        a = key[a];
        c = static_cast<uint8_t>(b + c);
        b = key[260];
        b = key[b];
        c = static_cast<uint8_t>(b + c);
        b = key[c];
        c = key[256];
        c = key[c];
        a = static_cast<uint8_t>(a + c);
        c = key[b];
        b = key[a];
        c ^= b ^ d;
        key[260] = c;
        key[259] = d;
        return c;
    }
};

// EncryptTypeX: a 20-byte header (7-byte prefix, 13 bytes mixed into the
// client's challenge to seed the cipher) followed by the encrypted payload.
std::vector<uint8_t> EncryptTypeX(std::string_view secret, std::array<uint8_t, 8> challenge,
                                  const std::vector<uint8_t>& payload) {
    constexpr int kHeaderSize = 20;
    constexpr int kPrefixSize = 7;
    std::vector<uint8_t> out(kHeaderSize);
    uint64_t rnd = static_cast<uint64_t>(std::time(nullptr));
    for (int i = 0; i < kHeaderSize; ++i) {
        rnd = rnd * 0x343FD + 0x269EC3;
        out[i] = static_cast<uint8_t>(rnd ^ static_cast<uint8_t>(secret[i % secret.size()]) ^
                                      challenge[i % challenge.size()]);
    }
    out[0] = static_cast<uint8_t>((kPrefixSize - 2) ^ 0xEC);
    out[1] = 0;
    out[2] = 0;
    out[kPrefixSize - 1] = static_cast<uint8_t>((kHeaderSize - kPrefixSize) ^ 0xEA);

    // enctypexFuncX over header bytes [7, 20).
    for (int i = 0; i < kHeaderSize - kPrefixSize; ++i) {
        const uint8_t secretByte = static_cast<uint8_t>(secret[i % secret.size()]);
        challenge[(secretByte * i) & 7] ^= challenge[i & 7] ^ out[kPrefixSize + i];
    }
    EncTypeX cipher;
    cipher.Shuffle(challenge.data(), static_cast<int>(challenge.size()));

    out.reserve(kHeaderSize + payload.size());
    for (const uint8_t byte : payload) {
        out.push_back(cipher.Encrypt(byte));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Filter evaluation: the SQL-like expressions DWC sends, e.g.
//   dwc_mver = 90 and dwc_pid != 1 and (rk = 'vs' and ev >= 1 and p = 0)
// With wfc-server's MKWii relaxations (filter/eval.go): every ev/eb comparison
// passes, and regional rk values like vs_10 compare as vs.

class Filter {
public:
    Filter(std::string_view text, const KeyValues& server) : text_(text), server_(server) {}

    std::optional<bool> Evaluate() {
        Next();
        const auto result = Or();
        if (!result || token_.kind != Kind::End) return std::nullopt;
        return result;
    }

private:
    enum class Kind { End, Ident, Number, String, Op, LParen, RParen, Error };
    struct Token {
        Kind kind = Kind::End;
        std::string text;
    };

    void Next() {
        while (pos_ < text_.size() && std::isspace(static_cast<unsigned char>(text_[pos_]))) ++pos_;
        token_ = {};
        if (pos_ >= text_.size()) return;
        const char ch = text_[pos_];
        if (std::isalpha(static_cast<unsigned char>(ch)) || ch == '_') {
            const size_t start = pos_;
            while (pos_ < text_.size() &&
                   (std::isalnum(static_cast<unsigned char>(text_[pos_])) || text_[pos_] == '_')) {
                ++pos_;
            }
            token_ = {Kind::Ident, std::string(text_.substr(start, pos_ - start))};
        } else if (std::isdigit(static_cast<unsigned char>(ch)) || ch == '-' || ch == '.') {
            const size_t start = pos_++;
            while (pos_ < text_.size() &&
                   (std::isdigit(static_cast<unsigned char>(text_[pos_])) || text_[pos_] == '.')) {
                ++pos_;
            }
            token_ = {Kind::Number, std::string(text_.substr(start, pos_ - start))};
        } else if (ch == '\'') {
            const size_t end = text_.find('\'', pos_ + 1);
            if (end == std::string_view::npos) {
                token_ = {Kind::Error, {}};
                pos_ = text_.size();
                return;
            }
            token_ = {Kind::String, std::string(text_.substr(pos_ + 1, end - pos_ - 1))};
            pos_ = end + 1;
        } else if (ch == '(' || ch == ')') {
            token_ = {ch == '(' ? Kind::LParen : Kind::RParen, std::string(1, ch)};
            ++pos_;
        } else if (ch == '=' || ch == '!' || ch == '<' || ch == '>') {
            std::string op(1, ch);
            ++pos_;
            if (pos_ < text_.size() && (text_[pos_] == '=' || (ch == '<' && text_[pos_] == '>'))) {
                op.push_back(text_[pos_++]);
            }
            if (op == "==") op = "=";
            if (op == "<>") op = "!=";
            token_ = {Kind::Op, op};
        } else {
            token_ = {Kind::Error, std::string(1, ch)};
            ++pos_;
        }
    }

    bool IsKeyword(const char* keyword) const {
        return token_.kind == Kind::Ident && Lower(token_.text) == keyword;
    }

    std::optional<bool> Or() {
        auto left = And();
        while (left && IsKeyword("or")) {
            Next();
            const auto right = And();
            if (!right) return std::nullopt;
            left = *left || *right;
        }
        return left;
    }

    std::optional<bool> And() {
        auto left = Unary();
        while (left && IsKeyword("and")) {
            Next();
            const auto right = Unary();
            if (!right) return std::nullopt;
            left = *left && *right;
        }
        return left;
    }

    std::optional<bool> Unary() {
        if (IsKeyword("not")) {
            Next();
            const auto inner = Unary();
            if (!inner) return std::nullopt;
            return !*inner;
        }
        if (token_.kind == Kind::LParen) {
            Next();
            const auto inner = Or();
            if (!inner || token_.kind != Kind::RParen) return std::nullopt;
            Next();
            return inner;
        }
        return Comparison();
    }

    struct Operand {
        std::string value;
        std::string name;  // set for identifiers
    };

    std::optional<Operand> ReadOperand() {
        Operand operand;
        if (token_.kind == Kind::Ident) {
            operand.name = token_.text;
            const auto it = server_.find(token_.text);
            operand.value = it == server_.end() ? std::string() : it->second;
        } else if (token_.kind == Kind::Number || token_.kind == Kind::String) {
            operand.value = token_.text;
        } else {
            return std::nullopt;
        }
        Next();
        return operand;
    }

    static std::optional<double> AsNumber(const std::string& text) {
        if (text.empty()) return std::nullopt;
        char* end = nullptr;
        const double value = std::strtod(text.c_str(), &end);
        if (end != text.c_str() + text.size()) return std::nullopt;
        return value;
    }

    std::optional<bool> Comparison() {
        auto left = ReadOperand();
        if (!left || token_.kind != Kind::Op) return std::nullopt;
        const std::string op = token_.text;
        Next();
        auto right = ReadOperand();
        if (!right) return std::nullopt;

        if (left->name == "ev" || left->name == "eb" || right->name == "ev" || right->name == "eb") {
            return true;
        }
        if (left->name == "rk" || right->name == "rk") {
            for (Operand* operand : {&*left, &*right}) {
                operand->value = operand->value.substr(0, operand->value.find('_'));
            }
        }

        int order = 0;
        const auto leftNumber = AsNumber(left->value);
        const auto rightNumber = AsNumber(right->value);
        if (leftNumber && rightNumber) {
            order = *leftNumber < *rightNumber ? -1 : (*leftNumber > *rightNumber ? 1 : 0);
        } else {
            order = left->value.compare(right->value);
            order = order < 0 ? -1 : (order > 0 ? 1 : 0);
        }
        if (op == "=") return order == 0;
        if (op == "!=") return order != 0;
        if (op == "<") return order < 0;
        if (op == "<=") return order <= 0;
        if (op == ">") return order > 0;
        if (op == ">=") return order >= 0;
        return std::nullopt;
    }

    std::string_view text_;
    const KeyValues& server_;
    size_t pos_ = 0;
    Token token_;
};

// ---------------------------------------------------------------------------

bool ReadCString(const std::vector<uint8_t>& packet, size_t& offset, std::string& out) {
    const auto begin = packet.begin() + static_cast<std::ptrdiff_t>(offset);
    const auto nul = std::find(begin, packet.end(), 0);
    if (nul == packet.end()) return false;
    out.assign(begin, nul);
    offset += out.size() + 1;
    return true;
}

void AppendU16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

void AppendU32(std::vector<uint8_t>& out, uint32_t value) {
    AppendU16(out, static_cast<uint16_t>(value >> 16));
    AppendU16(out, static_cast<uint16_t>(value));
}

// Lists the servers matching `filter`. "dwc_pid = X" is DWC's self/friend
// lookup: as wfc-server does, a session that has not reported its dwc_pid yet
// but shares the caller's public IP also matches.
// `pidLookupPending` is set when the lookup matched only through that
// fallback: the session's heartbeat with its dwc_pid hasn't arrived yet.
std::vector<KeyValues> MatchServers(const std::string& filter, const std::string& callerIp,
                                    bool* pidLookupPending = nullptr) {
    std::vector<KeyValues> matches;
    bool exactPid = false;
    bool fallbackPid = false;
    const std::vector<KeyValues> servers = Qr2Servers();
    std::string lookupPid;
    {
        std::string compact;
        for (const char ch : filter) {
            if (ch != ' ') compact.push_back(ch);
        }
        if (compact.rfind("dwc_pid=", 0) == 0 &&
            compact.find_first_not_of("0123456789", 8) == std::string::npos && compact.size() > 8) {
            lookupPid = compact.substr(8);
        }
    }
    for (const KeyValues& server : servers) {
        if (!lookupPid.empty()) {
            const auto pid = server.find("dwc_pid");
            if (pid != server.end() && pid->second == lookupPid) {
                exactPid = true;
                matches.push_back(server);
            } else if (pid == server.end() && server.at("publicip") == callerIp) {
                fallbackPid = true;
                matches.push_back(server);
            }
            continue;
        }
        const auto result = Filter(filter, server).Evaluate();
        if (!result) {
            Log("sb: could not evaluate filter: %s", filter.c_str());
            return {};
        }
        if (*result) {
            matches.push_back(server);
        }
    }
    if (pidLookupPending) {
        *pidLookupPending = fallbackPid && !exactPid;
    }
    return matches;
}

class ServerBrowserSession final : public TcpSession {
public:
    void OnData(TcpLink& link, std::vector<uint8_t>& buffer) override {
        while (buffer.size() >= 3) {
            const size_t size = (static_cast<size_t>(buffer[0]) << 8) | buffer[1];
            if (size < 3 || size > 0x1000) {
                Log("%s sb: invalid packet size %zu, closing", link.Label().c_str(), size);
                link.Close();
                return;
            }
            if (buffer.size() < size) {
                return;
            }
            const std::vector<uint8_t> packet(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(size));
            buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(size));
            switch (packet[2]) {
            case kServerList:
                ServerList(link, packet, true);
                break;
            case kKeepaliveReply:
                break;
            case kSendMessage:
                SendMessage(link, packet);
                break;
            default:
                LogPayload((link.Label() + " sb: unhandled request").c_str(), packet.data(), packet.size());
                break;
            }
        }
    }

    void OnTick(TcpLink& link) override {
        if (pendingList_.empty()) {
            return;
        }
        // Answer once the heartbeat with the caller's dwc_pid has arrived,
        // or with what there is after a second.
        const bool expired = std::chrono::steady_clock::now() >= pendingDeadline_;
        std::vector<uint8_t> packet = pendingList_;
        pendingList_.clear();
        ServerList(link, packet, !expired);
    }

private:
    // A self lookup ("dwc_pid = own pid") answered before the caller's
    // heartbeat carrying its dwc_pid would list its stale login-time record,
    // which DWC ignores, retrying only after 3 s. Such a request waits here.
    std::vector<uint8_t> pendingList_;
    std::chrono::steady_clock::time_point pendingDeadline_{};

    // serverbrowser/server.go handleSendMessageRequest: size, type, then the
    // target as listed (ip u32, port u16, big-endian) and the message for it,
    // a NAT negotiation cookie or a DWC match command.
    static void SendMessage(TcpLink& link, const std::vector<uint8_t>& packet) {
        if (packet.size() < 9) {
            return;
        }
        sockaddr_in target{};
        target.sin_family = AF_INET;
        target.sin_addr.s_addr = htonl(GetU32(packet.data() + 3));
        target.sin_port = htons(GetU16(packet.data() + 7));
        Log("%s sb: message for %s:%u", link.Label().c_str(), FormatAddress(target).c_str(),
            ntohs(target.sin_port));
        SendQr2ClientMessage(target, packet.data() + 9, packet.size() - 9);
    }

    // `mayWait`: a self lookup whose heartbeat hasn't arrived may be held
    // (see pendingList_) instead of answered.
    void ServerList(TcpLink& link, const std::vector<uint8_t>& packet, bool mayWait) {
        // Bytes 3..8: list version, encoding version, game version.
        size_t offset = 9;
        std::string queryGame;
        std::string gameName;
        std::string filter;
        std::string fields;
        std::array<uint8_t, 8> challenge{};
        if (!ReadCString(packet, offset, queryGame) || !ReadCString(packet, offset, gameName) ||
            offset + challenge.size() > packet.size()) {
            Log("%s sb: malformed server list request", link.Label().c_str());
            return;
        }
        std::copy_n(packet.begin() + static_cast<std::ptrdiff_t>(offset), challenge.size(), challenge.begin());
        offset += challenge.size();
        if (!ReadCString(packet, offset, filter) || !ReadCString(packet, offset, fields) ||
            offset + 4 > packet.size()) {
            Log("%s sb: malformed server list request", link.Label().c_str());
            return;
        }
        const uint32_t options = (static_cast<uint32_t>(packet[offset]) << 24) |
            (static_cast<uint32_t>(packet[offset + 1]) << 16) |
            (static_cast<uint32_t>(packet[offset + 2]) << 8) | packet[offset + 3];
        const bool listServers = (options & kNoServerListOption) == 0;

        std::vector<std::string> fieldList;
        if (listServers) {
            size_t start = 0;
            while (start <= fields.size()) {
                size_t end = fields.find('\\', start);
                if (end == std::string::npos) end = fields.size();
                const std::string field = fields.substr(start, end - start);
                start = end + 1;
                // Private address fields are never sent as keys.
                if (field.empty() || field == " " || field == "publicip" || field == "publicport" ||
                    field.rfind("localip", 0) == 0 || field == "localport") {
                    continue;
                }
                fieldList.push_back(field);
            }
        }

        const sockaddr_in& caller = link.Peer();
        std::vector<uint8_t> out;
        AppendU32(out, ntohl(caller.sin_addr.s_addr));
        AppendU16(out, ntohs(caller.sin_port));
        out.push_back(static_cast<uint8_t>(fieldList.size()));
        for (const std::string& field : fieldList) {
            out.push_back(0x00);  // key type: string
            out.insert(out.end(), field.begin(), field.end());
            out.push_back(0x00);
        }
        out.push_back(0x00);  // no popular values

        std::vector<KeyValues> servers;
        if (listServers && !filter.empty() && filter != " " && filter != "0") {
            bool pidLookupPending = false;
            servers = MatchServers(filter, GameSpyIp(caller), &pidLookupPending);
            if (pidLookupPending && mayWait) {
                if (pendingList_.empty() && pendingDeadline_ == std::chrono::steady_clock::time_point{}) {
                    pendingDeadline_ = std::chrono::steady_clock::now() + std::chrono::seconds(1);
                }
                pendingList_ = packet;
                return;
            }
        }
        pendingDeadline_ = {};
        Log("%s sb: list '%s' filter '%s' fields '%s' -> %zu server(s)", link.Label().c_str(),
            queryGame.c_str(), filter.c_str(), fields.c_str(), servers.size());

        for (const KeyValues& server : servers) {
            const auto find = [&](const char* key) -> std::optional<std::string> {
                const auto it = server.find(key);
                if (it == server.end()) return std::nullopt;
                return it->second;
            };
            // Every listed address is a virtual IP that the relay reaches
            // directly, so no listing asks for NAT negotiation, and the
            // private address is zeroed as in wfc-server's hidden-IP branch:
            // the game must use the virtual public address, never its LAN one.
            const uint8_t flags =
                kHasKeys | kNonstandardPort | kPrivateIp | kNonstandardPrivatePort | kIcmpIp;
            std::vector<uint8_t> address;
            AppendU32(address, static_cast<uint32_t>(std::stoll(server.at("publicip"))));
            const uint16_t port = static_cast<uint16_t>(std::stoul(server.at("publicport")));
            if (port < 1024) continue;
            AppendU16(address, port);
            AppendU32(address, 0);  // private IP
            AppendU16(address, 0);  // private port
            AppendU32(address, 0);  // ICMP address

            out.push_back(flags);
            out.insert(out.end(), address.begin(), address.end());
            for (const std::string& field : fieldList) {
                out.push_back(0xFF);
                if (const auto value = find(field.c_str())) {
                    out.insert(out.end(), value->begin(), value->end());
                }
                out.push_back(0x00);
            }
        }
        if (listServers) {
            out.insert(out.end(), {0x00, 0xFF, 0xFF, 0xFF, 0xFF});
        }

        const std::vector<uint8_t> encrypted = EncryptTypeX(kSecretKey, challenge, out);
        link.Send(encrypted.data(), encrypted.size());
    }
};

}  // namespace

std::unique_ptr<TcpSession> CreateServerBrowserSession() {
    return std::make_unique<ServerBrowserSession>();
}

}  // namespace NetworkHle::DirectOnline
