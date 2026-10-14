// GPCM (GameSpy Presence, TCP 29900) side of the built-in WFC server: login
// against the NAS token, presence status, profile lookups and keepalives.
// Protocol reference: WiiLink wfc-server, gpcm/main.go, gpcm/login.go,
// gpcm/profile.go, gpcm/friend.go and common/gamespy_message.go.

#include "direct_server.h"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>

#include <map>
#include <set>

namespace NetworkHle::DirectOnline {

namespace {

struct GameSpyCommand {
    std::string name;
    std::string value;
    std::map<std::string, std::string> fields;

    std::string Field(const char* key) const {
        const auto it = fields.find(key);
        return it == fields.end() ? std::string() : it->second;
    }
    bool Has(const char* key) const { return fields.count(key) != 0; }
};

// One command: \name\value\key\value...\final\ (the trailing \final\ included).
std::optional<GameSpyCommand> ParseCommand(std::string_view message) {
    if (message.empty() || message.front() != '\\') {
        return std::nullopt;
    }
    message.remove_prefix(1);
    std::vector<std::string_view> tokens;
    while (!message.empty()) {
        const size_t end = message.find('\\');
        tokens.push_back(message.substr(0, end));
        if (end == std::string_view::npos) break;
        message.remove_prefix(end + 1);
    }
    GameSpyCommand command;
    for (size_t i = 0; i < tokens.size(); i += 2) {
        const std::string_view key = tokens[i];
        if (key == "final") break;
        const std::string_view value = i + 1 < tokens.size() ? tokens[i + 1] : std::string_view();
        if (command.name.empty()) {
            command.name = key;
            command.value = value;
        } else {
            command.fields[std::string(key)] = std::string(value);
        }
    }
    if (command.name.empty()) {
        return std::nullopt;
    }
    return command;
}

std::string FormatCommand(std::string_view name, std::string_view value,
                          std::initializer_list<std::pair<const char*, std::string>> fields) {
    std::string out = "\\";
    out += name;
    out += "\\";
    out += value;
    for (const auto& [key, field] : fields) {
        out += "\\";
        out += key;
        out += "\\";
        out += field;
    }
    out += "\\final\\";
    return out;
}

std::string Md5Hex(std::string_view text) {
    CryptoPP::Weak::MD5 md5;
    std::array<uint8_t, CryptoPP::Weak::MD5::DIGESTSIZE> digest{};
    md5.CalculateDigest(digest.data(), reinterpret_cast<const CryptoPP::byte*>(text.data()), text.size());
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    for (const uint8_t byte : digest) {
        out.push_back(kHex[byte >> 4]);
        out.push_back(kHex[byte & 15]);
    }
    return out;
}

// gpcm/login.go generateResponse: proof swaps the two challenges.
std::string LoginHash(const std::string& nasChallenge, const std::string& authToken,
                      const std::string& first, const std::string& second) {
    const std::string nasHash = Md5Hex(nasChallenge);
    return Md5Hex(nasHash + std::string(48, ' ') + authToken + first + second + nasHash);
}

std::string Base32(uint64_t value) {
    static constexpr char kAlphabet[] = "0123456789abcdefghijklmnopqrstuv";
    std::string out;
    for (; value > 0; value >>= 5) {
        out.insert(out.begin(), kAlphabet[value & 31]);
    }
    return out;
}

std::string StandardBase64(const uint8_t* data, size_t size) {
    std::string encoded = DwcBase64Encode(data, size);
    for (char& ch : encoded) {
        if (ch == '.') ch = '+';
        else if (ch == '-') ch = '/';
        else if (ch == '*') ch = '=';
    }
    return encoded;
}

std::string FriendCode(uint32_t profileId, std::string_view gameId) {
    if (gameId.size() < 4) {
        return "?";
    }
    const uint64_t code = FriendKey(profileId, gameId);
    char text[16];
    std::snprintf(text, sizeof(text), "%012" PRIu64, code);
    return std::string(text, 4) + "-" + std::string(text + 4, 4) + "-" + std::string(text + 8, 4);
}

// A stable profile id for a client that does not send its own: derived from
// what NAS knows about it, so the same save gets the same id every login.
uint32_t DeriveProfileId(uint64_t userId, std::string_view gsbrCode) {
    uint32_t hash = 2166136261u;
    auto mix = [&](uint8_t byte) {
        hash ^= byte;
        hash *= 16777619u;
    };
    for (int shift = 0; shift < 64; shift += 8) mix(static_cast<uint8_t>(userId >> shift));
    for (const char ch : gsbrCode) mix(static_cast<uint8_t>(ch));
    // Stay in wfc-server's range: positive, at least 1,000,000,000.
    return 1000000000u + hash % 1000000000u;
}

// Profile fields a client sets with \updatepro\ and reads back in \pi\.
// DWC's first login with a new profile depends on this: it writes its login
// id into lastname, reads the profile again and only completes the login
// (saving the profile id) once the lastname matches (DWCi_GPGetInfoCallback,
// 0x800D0A74). Kept per profile id for the server's lifetime.
struct ProfileFields {
    std::string firstName;
    std::string lastName;
};
std::map<uint32_t, ProfileFields> g_profiles;

enum class GpError : int {
    Parse = 0x001,
    NotLoggedIn = 0x002,
    Login = 0x100,
    GetProfileBadProfile = 0xA01,
};

class GpcmSession;

// Logged-in GPCM sessions by profile id, for friend requests and status.
std::map<uint32_t, GpcmSession*> g_gpcmSessions;

// GPCM login tickets (\lc\2 lt) to the profile id they were issued to.
std::map<std::string, uint32_t> g_loginTickets;

// What a friend sees once a player logs out (gpcm/friend.go logOutMessage).
constexpr std::string_view kLogOutStatus = "|s|0|ss|Offline|ls||ip|0|p|0|qm|0";

// Friends follow wfc-server's gpcm/friend.go with every player treated as an
// "open host": anyone who adds a player is authorized at once, so players on
// the same host become friends as soon as their games list each other.
class GpcmSession final : public TcpSession {
public:
    ~GpcmSession() override {
        if (!loggedIn_) {
            return;
        }
        // gpcm/friend.go sendLogoutStatus.
        for (const uint32_t friendId : authorized_) {
            if (GpcmSession* other = Find(friendId)) {
                other->authorized_.erase(profileId_);
                other->SendBuddyMessage("100", profileId_, kLogOutStatus);
            }
        }
        const auto it = g_gpcmSessions.find(profileId_);
        if (it != g_gpcmSessions.end() && it->second == this) {
            g_gpcmSessions.erase(it);
            SetKnownPlayers(OnlineProfileIds());
        }
    }

    void OnOpen(TcpLink& link) override {
        link_ = &link;
        challenge_ = RandomUpper(10);
        link.Send(FormatCommand("lc", "1", {{"challenge", challenge_}, {"id", "1"}}));
    }

    void OnData(TcpLink& link, std::vector<uint8_t>& buffer) override {
        if (buffer.size() > 0x4000) {
            Log("%s gpcm: oversized message, closing", link.Label().c_str());
            SendError(link, GpError::Parse, "Parse error.", true);
            return;
        }
        static constexpr std::string_view kFinal = "\\final\\";
        for (;;) {
            const std::string_view data(reinterpret_cast<const char*>(buffer.data()), buffer.size());
            const size_t end = data.find(kFinal);
            if (end == std::string_view::npos) {
                return;
            }
            const std::string message(data.substr(0, end + kFinal.size()));
            buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(message.size()));
            const auto command = ParseCommand(message);
            if (!command || message.find('\0') != std::string::npos) {
                LogPayload("gpcm: unparseable message", reinterpret_cast<const uint8_t*>(message.data()),
                           message.size());
                SendError(link, GpError::Parse, "Parse error.", true);
                return;
            }
            Handle(link, *command);
        }
    }

private:
    void Handle(TcpLink& link, const GameSpyCommand& command) {
        if (command.name == "ka") {
            link.Send("\\ka\\\\final\\");
            return;
        }
        if (command.name == "login") {
            Login(link, command);
            return;
        }
        if (command.name == "logout") {
            return;
        }
        if (!loggedIn_) {
            Log("%s gpcm: '%s' before login", link.Label().c_str(), command.name.c_str());
            SendError(link, GpError::NotLoggedIn, "There was an error logging in to the GP backend.", true);
            return;
        }
        if (command.name == "status") {
            status_ = command.value;
            statString_ = command.Field("statstring");
            locString_ = command.Field("locstring");
            Log("%s gpcm: status %s statstring='%s' locstring='%s'", link.Label().c_str(),
                status_.c_str(), statString_.c_str(), locString_.c_str());
            if (!statusSet_) {
                statusSet_ = true;
                AuthorizeWaitingFriends();
            }
            for (const uint32_t friendId : authorized_) {
                SendStatusTo(friendId);
            }
            return;
        }
        if (command.name == "bm") {
            RelayBuddyMessage(command);
            return;
        }
        if (command.name == "addbuddy") {
            AddBuddy(command);
            return;
        }
        if (command.name == "delbuddy") {
            uint32_t friendId = 0;
            ParseProfileId(command.Field("delprofileid"), friendId);
            friends_.erase(friendId);
            Log("%s gpcm: delbuddy %u", link.Label().c_str(), friendId);
            return;
        }
        if (command.name == "authadd") {
            uint32_t friendId = 0;
            ParseProfileId(command.Field("fromprofileid"), friendId);
            Log("%s gpcm: authadd %u", link.Label().c_str(), friendId);
            if (authorized_.count(friendId)) {
                ExchangeStatus(friendId);
            }
            return;
        }
        if (command.name == "getprofile") {
            GetProfile(link, command);
            return;
        }
        if (command.name == "updatepro") {
            ProfileFields& fields = g_profiles[profileId_];
            if (command.Has("firstname")) fields.firstName = command.Field("firstname");
            if (command.Has("lastname")) fields.lastName = command.Field("lastname");
            Log("%s gpcm: updatepro firstname='%s' lastname='%s'", link.Label().c_str(),
                fields.firstName.c_str(), fields.lastName.c_str());
            return;
        }
        const std::string text = MessageText(command);
        LogPayload((link.Label() + " gpcm: unhandled '" + command.name + "'").c_str(),
                   reinterpret_cast<const uint8_t*>(text.data()), text.size());
    }

    static std::string MessageText(const GameSpyCommand& command) {
        std::string out = "\\" + command.name + "\\" + command.value;
        for (const auto& [key, value] : command.fields) out += "\\" + key + "\\" + value;
        return out;
    }

    void Login(TcpLink& link, const GameSpyCommand& command) {
        if (loggedIn_) {
            SendError(link, GpError::Login, "There was an error logging in to the GP backend.", true);
            return;
        }
        const std::string authToken = command.Field("authtoken");
        const std::string clientChallenge = command.Field("challenge");
        const auto login = FindNasLogin(authToken);
        if (!login) {
            Log("%s gpcm: login with an unknown auth token", link.Label().c_str());
            SendError(link, GpError::Login, "There was an error logging in to the GP backend.", true);
            return;
        }
        const std::string expected = LoginHash(login->challenge, authToken, clientChallenge, challenge_);
        if (command.Field("response") != expected) {
            Log("%s gpcm: login response mismatch", link.Label().c_str());
            SendError(link, GpError::Login, "There was an error logging in to the GP backend.", true);
            return;
        }

        // Profile id precedence: what the client asks for, then what its save
        // already holds (it rejects any other id), then a stable derived one.
        uint32_t profileId = 0;
        const char* source = "requested";
        const std::string requested = command.Field("profileid");
        std::from_chars(requested.data(), requested.data() + requested.size(), profileId);
        if (profileId == 0) {
            if (const auto stored = link.StoredProfileId(login->userId)) {
                profileId = *stored;
                source = "from save";
            } else {
                profileId = DeriveProfileId(login->userId, login->gsbrCode);
                source = "derived";
            }
        }

        profileId_ = profileId;
        userId_ = login->userId;
        gsbrCode_ = login->gsbrCode;
        uniqueNick_ = Base32(login->userId) + login->gsbrCode;
        loggedIn_ = true;
        // A second login with the same profile replaces the first, whose
        // connection is on its way out.
        g_gpcmSessions[profileId_] = this;
        SetKnownPlayers(OnlineProfileIds());

        std::array<uint8_t, 16> ticket{};
        for (size_t i = 0; i < ticket.size(); i += 8) {
            const uint64_t value = RandomU64();
            std::memcpy(ticket.data() + i, &value, 8);
        }
        const uint32_t sessionKey = 10000000u + static_cast<uint32_t>(RandomU64() % 290000000u);
        const std::string loginTicket = StandardBase64(ticket.data(), ticket.size());
        // Sake requests carry this ticket to say whose records they are.
        g_loginTickets[loginTicket] = profileId_;

        Log("%s gpcm: login gamename=%s profileid=%u (%s) friend code %s", link.Label().c_str(),
            command.Field("gamename").c_str(), profileId_, source,
            FriendCode(profileId_, login->gsbrCode).c_str());
        const std::string loginText = MessageText(command);
        LogPayload((link.Label() + " gpcm: login fields").c_str(),
                   reinterpret_cast<const uint8_t*>(loginText.data()), loginText.size());

        link.Send(FormatCommand("lc", "2", {
            {"sesskey", std::to_string(sessionKey)},
            {"proof", LoginHash(login->challenge, authToken, challenge_, clientChallenge)},
            {"userid", std::to_string(userId_)},
            {"profileid", std::to_string(profileId_)},
            {"uniquenick", uniqueNick_},
            {"lt", loginTicket},
            {"id", command.Field("id")},
        }));
    }

    void GetProfile(TcpLink& link, const GameSpyCommand& command) {
        const std::string requested = command.Field("profileid");
        uint32_t profileId = 0;
        std::from_chars(requested.data(), requested.data() + requested.size(), profileId);
        std::array<uint8_t, 16> sig{};
        for (size_t i = 0; i < sig.size(); i += 8) {
            const uint64_t value = RandomU64();
            std::memcpy(sig.data() + i, &value, 8);
        }
        std::string sigHex;
        for (const uint8_t byte : sig) {
            char hex[3];
            std::snprintf(hex, sizeof(hex), "%02x", byte);
            sigHex += hex;
        }
        if (profileId != profileId_) {
            const GpcmSession* other = Find(profileId);
            if (!other) {
                Log("%s gpcm: getprofile %s (not online)", link.Label().c_str(), requested.c_str());
                SendError(link, GpError::GetProfileBadProfile, "The profile requested is invalid.", false);
                return;
            }
            // Another player: gpcm/profile.go hides their ids behind the
            // generic DWC nick.
            const std::string genericNick = "000000000" + other->gsbrCode_.substr(0, 4) + "0000000";
            Log("%s gpcm: getprofile %s (online player)", link.Label().c_str(), requested.c_str());
            link.Send(FormatCommand("pi", "", {
                {"profileid", requested},
                {"nick", genericNick},
                {"userid", "0"},
                {"email", genericNick + "@nds"},
                {"sig", sigHex},
                {"uniquenick", genericNick},
                {"firstname", g_profiles[profileId].firstName},
                {"lastname", genericNick},
                {"pid", "11"},
                {"lon", "0.000000"},
                {"lat", "0.000000"},
                {"loc", other->locString_},
                {"id", command.Field("id")},
            }));
            return;
        }
        const ProfileFields& fields = g_profiles[profileId_];
        Log("%s gpcm: getprofile %s (own, lastname='%s')", link.Label().c_str(), requested.c_str(),
            fields.lastName.c_str());
        link.Send(FormatCommand("pi", "", {
            {"profileid", requested},
            {"nick", uniqueNick_},
            {"userid", std::to_string(userId_)},
            {"email", uniqueNick_ + "@nds"},
            {"sig", sigHex},
            {"uniquenick", uniqueNick_},
            {"firstname", fields.firstName},
            {"lastname", fields.lastName},
            {"pid", "11"},
            {"lon", "0.000000"},
            {"lat", "0.000000"},
            {"loc", locString_},
            {"id", command.Field("id")},
        }));
    }

    static GpcmSession* Find(uint32_t profileId) {
        const auto it = g_gpcmSessions.find(profileId);
        return it == g_gpcmSessions.end() ? nullptr : it->second;
    }

    static bool ParseProfileId(const std::string& text, uint32_t& profileId) {
        const auto result = std::from_chars(text.data(), text.data() + text.size(), profileId);
        return result.ec == std::errc() && profileId != 0;
    }

    // \bm\: a buddy message to this session's client "from" another profile.
    void SendBuddyMessage(std::string_view type, uint32_t from, std::string_view message) {
        link_->Send(FormatCommand("bm", std::string(type), {
            {"f", std::to_string(from)},
            {"msg", std::string(message)},
        }));
    }

    std::string StatusMessage() const {
        return "|s|" + status_ + "|ss|" + statString_ + "|ls|" + locString_ + "|ip|0|p|0|qm|0";
    }

    // gpcm/friend.go sendFriendStatus: our status to an authorized friend
    // who has us on their list.
    void SendStatusTo(uint32_t friendId) {
        GpcmSession* other = Find(friendId);
        if (statusSet_ && other && authorized_.count(friendId) && other->friends_.count(profileId_)) {
            other->SendBuddyMessage("100", profileId_, StatusMessage());
        }
    }

    // gpcm/friend.go exchangeFriendStatus.
    void ExchangeStatus(uint32_t friendId) {
        SendStatusTo(friendId);
        if (GpcmSession* other = Find(friendId)) {
            other->SendStatusTo(profileId_);
        }
    }

    // Makes two sessions friends and tells the one that asked.
    void Authorize(GpcmSession& other) {
        authorized_.insert(other.profileId_);
        other.authorized_.insert(profileId_);
        Log("%s gpcm: %u and %u are now friends", link_->Label().c_str(), profileId_, other.profileId_);
    }

    void AddBuddy(const GameSpyCommand& command) {
        uint32_t friendId = 0;
        if (!ParseProfileId(command.Field("newprofileid"), friendId) || friendId == profileId_) {
            Log("%s gpcm: addbuddy with a bad profile id '%s'", link_->Label().c_str(),
                command.Field("newprofileid").c_str());
            return;
        }
        friends_.insert(friendId);
        GpcmSession* other = Find(friendId);
        Log("%s gpcm: addbuddy %u (%s)", link_->Label().c_str(), friendId, other ? "online" : "not online");
        if (!other) {
            return;
        }
        if (!authorized_.count(friendId)) {
            Authorize(*other);
        }
        // "friendId authorized your request", then each other's status.
        SendBuddyMessage("4", friendId, "");
        if (other->friends_.count(profileId_)) {
            other->SendBuddyMessage("4", profileId_, "");
        }
        ExchangeStatus(friendId);
    }

    // gpcm/message.go bestieMessage: DWC's friend-room match commands
    // ("GPCM90vMAT" + command byte + DWC base64 data) travel as buddy
    // messages to the profile in \t\. Relayed as-is, except that a
    // reservation's local address is zeroed, as wfc-server does for players
    // on different networks: peers must use the virtual (relayed) address.
    void RelayBuddyMessage(const GameSpyCommand& command) {
        static constexpr std::string_view kPrefix = "GPCM90vMAT";
        static constexpr std::string_view kDeny = "GPCM90vMAT\x03" "EAAAAA**";
        uint32_t target = 0;
        ParseProfileId(command.Field("t"), target);
        std::string message = command.Field("msg");
        if (command.value != "1" || message.size() <= kPrefix.size() || message.compare(0, kPrefix.size(), kPrefix) != 0) {
            Log("%s gpcm: unsupported buddy message type %s to %u", link_->Label().c_str(),
                command.value.c_str(), target);
            return;
        }
        GpcmSession* other = Find(target);
        if (!other || !authorized_.count(target)) {
            Log("%s gpcm: match command to %u, who is %s; denying", link_->Label().c_str(), target,
                other ? "not a friend" : "not online");
            SendBuddyMessage("1", target, kDeny);
            return;
        }

        const uint8_t matchCommand = static_cast<uint8_t>(message[kPrefix.size()]);
        if (auto data = DwcBase64Decode(std::string_view(message).substr(kPrefix.size() + 1))) {
            if (matchCommand == 0x01 && data->size() >= 0x24) {
                Log("%s gpcm: reservation to %u: public %u.%u.%u.%u:%u, local %u.%u.%u.%u:%u (cleared)",
                    link_->Label().c_str(), target, (*data)[4], (*data)[5], (*data)[6], (*data)[7],
                    (*data)[8] | ((*data)[9] << 8), (*data)[0xC], (*data)[0xD], (*data)[0xE], (*data)[0xF],
                    (*data)[0x10] | ((*data)[0x11] << 8));
                std::fill(data->begin() + 0x0C, data->begin() + 0x14, uint8_t{0});
                message = std::string(kPrefix) + static_cast<char>(matchCommand) +
                    DwcBase64Encode(data->data(), data->size());
            } else {
                Log("%s gpcm: match command 0x%02X to %u (%zu bytes)", link_->Label().c_str(), matchCommand,
                    target, data->size());
            }
        }
        other->SendBuddyMessage("1", profileId_, message);
    }

    // gpcm/friend.go openHostEnabled: on our first status, authorize everyone
    // online who added us before we logged in.
    void AuthorizeWaitingFriends() {
        for (const auto& [otherId, other] : g_gpcmSessions) {
            if (other == this || !other->friends_.count(profileId_) || authorized_.count(otherId)) {
                continue;
            }
            Authorize(*other);
            other->SendBuddyMessage("4", profileId_, "");
        }
    }

    static void SendError(TcpLink& link, GpError error, const char* text, bool fatal) {
        std::string message = "\\error\\\\err\\" + std::to_string(static_cast<int>(error)) +
            "\\errmsg\\" + text;
        if (fatal) {
            message += "\\fatal\\";
        }
        message += "\\final\\";
        link.Send(message);
        if (fatal) {
            link.Close();
        }
    }

    TcpLink* link_ = nullptr;
    std::string challenge_;
    bool loggedIn_ = false;
    bool statusSet_ = false;
    uint32_t profileId_ = 0;
    uint64_t userId_ = 0;
    std::string gsbrCode_;
    std::string uniqueNick_;
    std::string status_;
    std::string statString_;
    std::string locString_;
    // Profiles this client has on its friend list (addbuddy), and the mutual
    // friendships the server has authorized.
    std::set<uint32_t> friends_;
    std::set<uint32_t> authorized_;
};

// GPSP (profile search, TCP 29901): the game asks which of its friends'
// profile ids exist (otherslist). gpsp/otherslist.go answers every listed id
// with the generic DWC nick; with no friends it is just \oldone.
class GpspSession final : public TcpSession {
public:
    void OnData(TcpLink& link, std::vector<uint8_t>& buffer) override {
        static constexpr std::string_view kFinal = "\\final\\";
        // The generic nick wfc-server reports for any other profile:
        // "000000000" + gsbrcd[0..4] + "0000000". MKWii's gsbrcd starts "RMCJ"
        // in every region.
        static constexpr std::string_view kOtherNick = "000000000RMCJ0000000";
        for (;;) {
            const std::string_view data(reinterpret_cast<const char*>(buffer.data()), buffer.size());
            const size_t end = data.find(kFinal);
            if (end == std::string_view::npos) {
                return;
            }
            const std::string message(data.substr(0, end + kFinal.size()));
            buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(message.size()));
            const auto command = ParseCommand(message);
            if (!command) {
                continue;
            }
            if (command->name == "ka") {
                link.Send("\\ka\\\\final\\");
            } else if (command->name == "otherslist") {
                std::string reply = "\\otherslist\\";
                const std::string ids = command->Field("opids");
                size_t start = 0;
                while (!ids.empty() && ids != "0" && start <= ids.size()) {
                    size_t split = ids.find('|', start);
                    if (split == std::string::npos) split = ids.size();
                    reply += "\\o\\" + ids.substr(start, split - start) + "\\uniquenick\\";
                    reply += kOtherNick;
                    start = split + 1;
                }
                reply += "\\oldone\\\\final\\";
                link.Send(reply);
                Log("%s gpsp: otherslist for %s (%s)", link.Label().c_str(),
                    command->Field("profileid").c_str(), ids.c_str());
            } else {
                LogPayload((link.Label() + " gpsp: unhandled '" + command->name + "'").c_str(),
                           reinterpret_cast<const uint8_t*>(message.data()), message.size());
            }
        }
    }
};

}  // namespace

// common/friend_code.go and DWC::CreateFriendKey (0x800EC6BC): the low 32
// bits are the profile id, the high bits half the first byte of an MD5 of it
// and the game id, both little-endian. MKWii's game id is "RMCJ".
uint64_t FriendKey(uint32_t profileId, std::string_view gameId) {
    std::array<uint8_t, 8> buffer{
        static_cast<uint8_t>(profileId), static_cast<uint8_t>(profileId >> 8),
        static_cast<uint8_t>(profileId >> 16), static_cast<uint8_t>(profileId >> 24),
        static_cast<uint8_t>(gameId[3]), static_cast<uint8_t>(gameId[2]),
        static_cast<uint8_t>(gameId[1]), static_cast<uint8_t>(gameId[0]),
    };
    CryptoPP::Weak::MD5 md5;
    std::array<uint8_t, CryptoPP::Weak::MD5::DIGESTSIZE> digest{};
    md5.CalculateDigest(digest.data(), buffer.data(), buffer.size());
    return profileId | (static_cast<uint64_t>(digest[0] >> 1) << 32);
}

std::optional<uint32_t> ProfileForLoginTicket(const std::string& loginTicket) {
    const auto it = g_loginTickets.find(loginTicket);
    if (it == g_loginTickets.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<uint32_t> OnlineProfileIds() {
    std::vector<uint32_t> ids;
    for (const auto& [profileId, session] : g_gpcmSessions) {
        ids.push_back(profileId);
    }
    return ids;
}

std::unique_ptr<TcpSession> CreateGpcmSession() {
    return std::make_unique<GpcmSession>();
}

std::unique_ptr<TcpSession> CreateGpspSession() {
    return std::make_unique<GpspSession>();
}

}  // namespace NetworkHle::DirectOnline
