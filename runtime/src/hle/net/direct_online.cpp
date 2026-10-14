#include "direct_online.h"
#include "direct_server.h"

#include "runtime_config.h"
#include "runtime_log.h"
#include "runtime_product.h"

#include <cryptopp/sha.h>

#include <atomic>
#include <condition_variable>
#include <fstream>
#include <mutex>
#include <random>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

namespace NetworkHle::DirectOnline {

namespace {

// Who this runtime's traffic goes to. Local is a host whose relay only
// listens on loopback, so playing alone and hosting share one code path.
enum class Mode { Local, Host, Client };

const char* ModeName(Mode mode) {
    switch (mode) {
    case Mode::Local: return "local";
    case Mode::Host: return "host";
    case Mode::Client: return "client";
    }
    return "?";
}

constexpr uint16_t kDefaultHostPort = 29999;

// Written once inside std::call_once, read-only afterwards: the emulation
// thread's address rewrites and the direct-mode thread both read it unlocked.
struct State {
    bool ready = false;
    Mode mode = Mode::Local;
    // Where this runtime's WFC traffic goes: the host's relay (our own, over
    // loopback, when hosting or playing alone).
    sockaddr_in relay{};
    // Identifies this runtime to the relay across its TCP and UDP traffic.
    uint64_t clientId = 0;
    // The `connect` value as configured, for messages.
    std::string connectTarget;
};
State g_state;
std::once_flag g_startOnce;

// The client's build check with the host, done on the direct-mode thread
// before the first forwarded connection. Unknown until the host answers.
enum class BuildCheck { Unknown, Accepted, Refused };
std::atomic<BuildCheck> g_buildCheck{BuildCheck::Unknown};

// Set once the direct-mode thread's first build check has finished, whatever
// its result. The game's first datagrams wait for it, since the relay drops
// datagrams from clients it hasn't checked.
std::mutex g_firstCheckMutex;
std::condition_variable g_firstCheckDone;
bool g_firstCheckFinished = false;

void FinishFirstCheck() {
    {
        std::lock_guard lock(g_firstCheckMutex);
        g_firstCheckFinished = true;
    }
    g_firstCheckDone.notify_all();
}

// Waits at most 3 s in total, counted from the first call, so a host that
// can't be reached delays only the first datagrams.
void WaitForFirstCheck() {
    static const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    std::unique_lock lock(g_firstCheckMutex);
    g_firstCheckDone.wait_until(lock, deadline, [] { return g_firstCheckFinished; });
}

// The game's WFC TCP connections land on these loopback front-ends, one per
// service port, and are forwarded to the relay. NAS is HTTPS (443) in the SDK,
// but the SSL HLE runs WFC hosts as plain TCP, so both HTTP ports forward alike.
struct FrontEnd {
    const char* name;
    uint16_t guestPort;
    NativeSocket socket = kInvalidSocket;
    uint16_t nativePort = 0;
};
std::vector<FrontEnd> g_frontEnds;

constexpr std::array<std::pair<const char*, uint16_t>, 5> kTcpServices = {{
    {"http", 80},
    {"https", 443},
    {"gpcm", 29900},
    {"gpsp", 29901},
    {"sb", 28910},
}};

bool SameEndpoint(const sockaddr_in& a, const sockaddr_in& b) {
    return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
}

void PreventSigPipe([[maybe_unused]] NativeSocket socket) {
#ifdef __APPLE__
    const int on = 1;
    setsockopt(socket, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
}

bool SendAll(NativeSocket socket, const void* data, size_t size) {
    const auto* bytes = static_cast<const char*>(data);
    size_t offset = 0;
    while (offset < size) {
        const int chunk = static_cast<int>(std::min<size_t>(size - offset, 64 * 1024));
        const int sent = ::send(socket, bytes + offset, chunk, SendFlags());
        if (sent <= 0) {
            return false;
        }
        offset += static_cast<size_t>(sent);
    }
    return true;
}

// Connects a blocking TCP socket to `address`, giving up after `timeoutMs`.
NativeSocket ConnectWithTimeout(const sockaddr_in& address, int timeoutMs) {
    NativeSocket socket = ::socket(AF_INET, SOCK_STREAM, 0);
    if (socket == kInvalidSocket) {
        return kInvalidSocket;
    }
    SetNonBlocking(socket, true);
    const int ret = ::connect(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
    if (ret != 0 && !IsWouldBlockError(NormalizeConnectError(NativeLastError()))) {
        CloseNativeSocket(socket);
        return kInvalidSocket;
    }
    if (ret != 0 && (ProbeConnectSettled(socket, timeoutMs) <= 0 || ClassifySettledConnect(socket) != 0)) {
        CloseNativeSocket(socket);
        return kInvalidSocket;
    }
    SetNonBlocking(socket, false);
    PreventSigPipe(socket);
    return socket;
}

// A game connection accepted on a front-end, piped to the relay.
class ForwardConnection {
public:
    ForwardConnection(NativeSocket game, NativeSocket upstream, std::string label)
        : game_(game), upstream_(upstream), label_(std::move(label)) {}
    ~ForwardConnection() {
        CloseNativeSocket(game_);
        CloseNativeSocket(upstream_);
    }

    void Watch(SocketSet& set) const {
        set.Watch(game_);
        set.Watch(upstream_);
    }

    // Returns false once either side has closed.
    bool Pump(const SocketSet& ready) {
        return (!ready.IsReady(game_) || Move(game_, upstream_)) &&
            (!ready.IsReady(upstream_) || Move(upstream_, game_));
    }

    const std::string& Label() const { return label_; }

private:
    static bool Move(NativeSocket from, NativeSocket to) {
        std::array<char, 16 * 1024> chunk{};
        const int received = ::recv(from, chunk.data(), static_cast<int>(chunk.size()), 0);
        return received > 0 && SendAll(to, chunk.data(), static_cast<size_t>(received));
    }

    NativeSocket game_;
    NativeSocket upstream_;
    std::string label_;
};

// Receives exactly `size` bytes, waiting at most `timeoutMs` for each read.
bool ReceiveExactly(NativeSocket socket, uint8_t* data, size_t size, int timeoutMs) {
    size_t offset = 0;
    while (offset < size) {
        SocketSet set;
        set.Clear();
        set.Watch(socket);
        set.Wait(timeoutMs);
        if (!set.IsReady(socket)) {
            return false;
        }
        const int received = ::recv(socket, reinterpret_cast<char*>(data + offset), static_cast<int>(size - offset), 0);
        if (received <= 0) {
            return false;
        }
        offset += static_cast<size_t>(received);
    }
    return true;
}

// Tells the player why joining failed; the game itself only shows an error
// code. Runs on its own thread so the dialog blocks neither the game nor the
// direct-mode thread.
// `host` is empty when the host runs a build from before build checks.
void ShowRefusal(const std::optional<BuildId>& host) {
    std::string message = "Can't join the host at " + g_state.connectTarget +
        ": it is running a different build.\n\n"
        "Host: " + (host ? host->Describe() : std::string("an older build")) + "\n"
        "You: " + LocalBuild().Describe() + "\n\n"
        "Everyone needs exactly the same build to play together. "
        "Ask the host for a copy of theirs.";
#if defined(_WIN32)
    std::thread([message = std::move(message)] {
        ::MessageBoxA(nullptr, message.c_str(), "WiiCompiled - Different Build",
                      MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
    }).detach();
#else
    Log("%s", message.c_str());
#endif
}

// Client mode: asks the host whether it accepts this build. Leaves the check
// Unknown when the host can't be reached, so the next connection asks again.
void CheckBuildWithHost(int timeoutMs) {
    const NativeSocket socket = ConnectWithTimeout(g_state.relay, timeoutMs);
    if (socket == kInvalidSocket) {
        Log("build check: could not reach the host at %s", FormatEndpoint(g_state.relay).c_str());
        return;
    }
    const BuildId& ours = LocalBuild();
    std::vector<uint8_t> hello(kHelloMagic.begin(), kHelloMagic.end());
    PutU64(hello, g_state.clientId);
    PutU64(hello, ours.fingerprint);
    hello.push_back(ours.product);
    std::array<uint8_t, kHelloReplySize> reply{};
    uint8_t playerCount = 0;
    std::vector<uint8_t> playerBytes;
    bool answered = SendAll(socket, hello.data(), hello.size()) &&
        ReceiveExactly(socket, reply.data(), reply.size(), timeoutMs) &&
        std::equal(kHelloMagic.begin(), kHelloMagic.end(), reply.begin()) &&
        ReceiveExactly(socket, &playerCount, 1, timeoutMs);
    if (answered) {
        playerBytes.resize(size_t{playerCount} * 4);
        answered = ReceiveExactly(socket, playerBytes.data(), playerBytes.size(), timeoutMs);
    }
    CloseNativeSocket(socket);
    std::vector<uint32_t> players;
    for (size_t i = 0; i + 4 <= playerBytes.size(); i += 4) {
        players.push_back(GetU32(playerBytes.data() + i));
    }
    if (!answered) {
        // A host on a build from before build checks closes the connection
        // without answering.
        Log("build check: the host at %s did not answer; it may run an older build",
            FormatEndpoint(g_state.relay).c_str());
        g_buildCheck = BuildCheck::Refused;
        ShowRefusal(std::nullopt);
        return;
    }
    const BuildId host{GetU64(reply.data() + 5), reply[13]};
    if (reply[4] == 1) {
        if (g_buildCheck != BuildCheck::Accepted) {
            Log("build check: the host accepted this build (%s)", ours.Describe().c_str());
        }
        g_buildCheck = BuildCheck::Accepted;
        SetKnownPlayers(std::move(players));
    } else {
        Log("build check: refused, the host runs %s and this is %s", host.Describe().c_str(),
            ours.Describe().c_str());
        g_buildCheck = BuildCheck::Refused;
        ShowRefusal(host);
    }
}

std::unique_ptr<ForwardConnection> OpenForward(const FrontEnd& frontEnd, NativeSocket game,
                                               const std::string& label) {
    constexpr int kConnectTimeoutMs = 5000;
    if (g_state.mode == Mode::Client && g_buildCheck == BuildCheck::Unknown) {
        CheckBuildWithHost(kConnectTimeoutMs);
    } else if (g_state.mode == Mode::Client && g_buildCheck == BuildCheck::Accepted && frontEnd.guestPort == 443) {
        // A NAS request starts a login: refresh the host's player list so the
        // friend list is current when GPCM logs in.
        static auto lastRefresh = std::chrono::steady_clock::time_point{};
        const auto now = std::chrono::steady_clock::now();
        if (now - lastRefresh >= std::chrono::seconds(2)) {
            lastRefresh = now;
            CheckBuildWithHost(kConnectTimeoutMs);
        }
    }
    if (g_buildCheck == BuildCheck::Refused) {
        // Closing at once makes the game fail fast with its own error code.
        Log("%s: not forwarded, the host refused this build", label.c_str());
        CloseNativeSocket(game);
        return nullptr;
    }
    const NativeSocket upstream = ConnectWithTimeout(g_state.relay, kConnectTimeoutMs);
    if (upstream == kInvalidSocket) {
        Log("%s: could not reach the relay at %s:%u", label.c_str(),
            FormatAddress(g_state.relay).c_str(), ntohs(g_state.relay.sin_port));
        CloseNativeSocket(game);
        return nullptr;
    }
    const StoredIdentity identity = ReadStoredIdentity();
    std::vector<uint8_t> preamble(kTcpMagic.begin(), kTcpMagic.end());
    PutU64(preamble, g_state.clientId);
    PutU16(preamble, frontEnd.guestPort);
    PutU64(preamble, identity.userId);
    PutU32(preamble, identity.profileId);
    PutU64(preamble, LocalBuild().fingerprint);
    preamble.push_back(LocalBuild().product);
    if (!SendAll(upstream, preamble.data(), preamble.size())) {
        Log("%s: relay closed the connection", label.c_str());
        CloseNativeSocket(game);
        CloseNativeSocket(upstream);
        return nullptr;
    }
    return std::make_unique<ForwardConnection>(game, upstream, label);
}

[[noreturn]] void Loop() {
    // Hash the executable before serving anything, so no connection waits on it.
    Log("this is %s", LocalBuild().Describe().c_str());
    // A client checks with the host straight away: the relay drops its
    // datagrams until then. If the host can't be reached yet, the first
    // forwarded connection asks again.
    if (g_state.mode == Mode::Client) {
        CheckBuildWithHost(5000);
    }
    FinishFirstCheck();
    std::vector<std::unique_ptr<ForwardConnection>> forwards;
    uint64_t nextConnectionId = 1;
    SocketSet sockets;

    for (;;) {
        sockets.Clear();
        for (const FrontEnd& frontEnd : g_frontEnds) {
            sockets.Watch(frontEnd.socket);
        }
        for (const auto& forward : forwards) {
            forward->Watch(sockets);
        }
        if (g_state.mode != Mode::Client) {
            RelayWatch(sockets);
        }

        sockets.Wait(100);

        // Keep the host's player list fresh, so players who arrive later
        // join the friend list too.
        if (g_state.mode == Mode::Client && g_buildCheck == BuildCheck::Accepted) {
            static auto nextRefresh = std::chrono::steady_clock::now() + std::chrono::seconds(10);
            if (std::chrono::steady_clock::now() >= nextRefresh) {
                nextRefresh = std::chrono::steady_clock::now() + std::chrono::seconds(10);
                CheckBuildWithHost(5000);
            }
        }

        for (const FrontEnd& frontEnd : g_frontEnds) {
            if (!sockets.IsReady(frontEnd.socket)) {
                continue;
            }
            const NativeSocket game = ::accept(frontEnd.socket, nullptr, nullptr);
            if (game == kInvalidSocket) {
                continue;
            }
            PreventSigPipe(game);
            const std::string label = std::string(frontEnd.name) + "-out#" + std::to_string(nextConnectionId++);
            if (auto forward = OpenForward(frontEnd, game, label)) {
                forwards.push_back(std::move(forward));
            }
        }

        for (auto it = forwards.begin(); it != forwards.end();) {
            if ((*it)->Pump(sockets)) {
                ++it;
            } else {
                it = forwards.erase(it);
            }
        }

        if (g_state.mode != Mode::Client) {
            RelayPump(sockets);
            Qr2Tick();
            NatnegTick();
        }
    }
}

std::optional<sockaddr_in> ResolveHost(const std::string& target) {
    const size_t colon = target.rfind(':');
    if (colon == std::string::npos || colon == 0) {
        return std::nullopt;
    }
    const std::string host = target.substr(0, colon);
    const std::string port = target.substr(colon + 1);
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* results = nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &results) != 0 || !results) {
        return std::nullopt;
    }
    sockaddr_in address{};
    std::memcpy(&address, results->ai_addr, sizeof(address));
    freeaddrinfo(results);
    return address;
}

void Start() {
    if (!EnsureSocketRuntime()) {
        Log("socket runtime unavailable, direct mode not started");
        return;
    }

    const std::string connect = RuntimeConfigFile::OnlineConnect();
    const bool host = RuntimeConfigFile::OnlineHost(false);
    g_state.mode = !connect.empty() ? Mode::Client : (host ? Mode::Host : Mode::Local);
    g_state.clientId = RandomU64() | 1;  // never 0: that marks relay -> client datagrams

    if (g_state.mode == Mode::Client) {
        const auto relay = ResolveHost(connect);
        if (!relay) {
            Log("could not resolve [online] connect = \"%s\" (expected address:port)", connect.c_str());
            return;
        }
        g_state.relay = *relay;
        g_state.connectTarget = connect;
    } else {
        const uint16_t requested = g_state.mode == Mode::Host
            ? static_cast<uint16_t>(RuntimeConfigFile::OnlinePort(kDefaultHostPort))
            : 0;
        uint16_t bound = 0;
        if (!StartRelay(g_state.mode == Mode::Host, requested, bound)) {
            return;
        }
        // Before the direct-mode thread exists, so no locking is needed.
        ApproveClient(g_state.clientId);
        g_state.relay.sin_family = AF_INET;
        g_state.relay.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        g_state.relay.sin_port = htons(bound);
    }

    for (const auto& [name, guestPort] : kTcpServices) {
        NativeSocket socket = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t length = sizeof(address);
        if (socket == kInvalidSocket ||
            ::bind(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
            ::listen(socket, 16) != 0 ||
            ::getsockname(socket, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
            Log("%s: could not open a loopback front-end (error %d)", name, NativeLastError());
            if (socket != kInvalidSocket) CloseNativeSocket(socket);
            continue;
        }
        g_frontEnds.push_back({name, guestPort, socket, ntohs(address.sin_port)});
    }

    Log("mode %s, relay %s:%u", ModeName(g_state.mode), FormatAddress(g_state.relay).c_str(),
        ntohs(g_state.relay.sin_port));
    g_state.ready = true;
    std::thread(Loop).detach();
}

void EnsureStarted() {
    std::call_once(g_startOnce, Start);
}

}  // namespace

}  // namespace NetworkHle::DirectOnline

// Called once at launch (main.cpp): a host starts its server and relay right
// away, so players can connect before the host goes online, and keeps them
// until the game closes. Clients and solo play start on first network use.
extern "C" void DirectOnline_StartHostAtLaunch() {
    using namespace NetworkHle::DirectOnline;
    if (Enabled() && RuntimeConfigFile::OnlineHost(false) && RuntimeConfigFile::OnlineConnect().empty()) {
        Log("hosting: starting the server at launch");
        EnsureStarted();
    }
}

namespace NetworkHle::DirectOnline {

std::string FormatAddress(const sockaddr_in& address) {
    char text[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &address.sin_addr, text, sizeof(text));
    return text;
}

namespace {

std::optional<std::filesystem::path> ExecutablePath() {
#if defined(_WIN32)
    std::wstring buffer(MAX_PATH, L'\0');
    for (;;) {
        const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) {
            return std::nullopt;
        }
        if (length < buffer.size() - 1) {
            buffer.resize(length);
            return std::filesystem::path(buffer);
        }
        buffer.resize(buffer.size() * 2);
    }
#elif defined(__APPLE__)
    uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size);
    std::string path(size, '\0');
    if (size == 0 || _NSGetExecutablePath(path.data(), &size) != 0) {
        return std::nullopt;
    }
    path.resize(std::char_traits<char>::length(path.c_str()));
    return std::filesystem::path(path);
#else
    return std::filesystem::path("/proc/self/exe");
#endif
}

BuildId ComputeLocalBuild() {
    BuildId build;
    build.product = static_cast<uint8_t>(RuntimeProduct::Active().kind);
    const auto path = ExecutablePath();
    std::ifstream file;
    if (path) {
        file.open(*path, std::ios::binary);
    }
    if (!file) {
        Log("build check: could not read the executable; only other unreadable builds will match");
        return build;
    }
    const auto start = std::chrono::steady_clock::now();
    CryptoPP::SHA256 sha;
    std::vector<char> chunk(1 << 20);
    while (file) {
        file.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
        sha.Update(reinterpret_cast<const CryptoPP::byte*>(chunk.data()), static_cast<size_t>(file.gcount()));
    }
    std::array<uint8_t, CryptoPP::SHA256::DIGESTSIZE> digest{};
    sha.Final(digest.data());
    build.fingerprint = GetU64(digest.data());
    Log("build check: hashed the executable in %lld ms",
        static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count()));
    return build;
}

}  // namespace

const BuildId& LocalBuild() {
    static const BuildId build = ComputeLocalBuild();
    return build;
}

std::string BuildId::Describe() const {
    const char* name = product == static_cast<uint8_t>(RuntimeProduct::Kind::RetroRewind) ? "Retro Rewind"
                                                                                          : "Mario Kart Wii";
    char hex[9];
    std::snprintf(hex, sizeof(hex), "%08x", static_cast<uint32_t>(fingerprint >> 32));
    return std::string(name) + " build " + hex;
}

void SocketSet::Clear() {
    FD_ZERO(&watched_);
    highest_ = 0;
}

void SocketSet::Watch(NativeSocket socket) {
    FD_SET(socket, &watched_);
    highest_ = std::max(highest_, socket);
}

void SocketSet::Wait(int timeoutMs) {
    ready_ = watched_;
    timeval timeout{};
    timeout.tv_sec = timeoutMs / 1000;
    timeout.tv_usec = (timeoutMs % 1000) * 1000;
    if (::select(static_cast<int>(highest_) + 1, &ready_, nullptr, nullptr, &timeout) <= 0) {
        FD_ZERO(&ready_);
    }
}

bool SocketSet::IsReady(NativeSocket socket) const {
    return FD_ISSET(socket, &ready_) != 0;
}

bool Enabled() {
    static const bool enabled = [] {
        const bool value = RuntimeConfigFile::OnlineDirect(false);
        if (value) {
            Log("direct-connect online enabled: WFC hostnames are served by the built-in server");
        }
        return value;
    }();
    return enabled;
}

bool IsWfcHost(std::string_view hostname) {
    const std::string lowered = Lower(hostname);
    auto isDomain = [&](std::string_view domain) {
        return lowered == domain ||
            (lowered.size() > domain.size() &&
             lowered.compare(lowered.size() - domain.size(), domain.size(), domain) == 0 &&
             lowered[lowered.size() - domain.size() - 1] == '.');
    };
    return isDomain("nintendowifi.net") || isDomain("gamespy.com");
}

bool ToNative(sockaddr_in& address) {
    if (ntohl(address.sin_addr.s_addr) != kPlaceholderIp) {
        return false;
    }
    EnsureStarted();
    const uint16_t guestPort = ntohs(address.sin_port);
    if (guestPort == 29900) {
        // On the emulation thread, before GPCM login: DWC sends a buddy
        // request for every friend list entry once it has logged in.
        AddKnownPlayersBeforeLogin();
    }
    for (const FrontEnd& frontEnd : g_frontEnds) {
        if (frontEnd.guestPort == guestPort) {
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            address.sin_port = htons(frontEnd.nativePort);
            return true;
        }
    }
    NetFail("direct: the game reached WFC TCP port %u, which direct mode does not serve", guestPort);
    return false;
}

bool ToGuest(sockaddr_in& address) {
    if (ntohl(address.sin_addr.s_addr) != INADDR_LOOPBACK) {
        return false;
    }
    const uint16_t nativePort = ntohs(address.sin_port);
    for (const FrontEnd& frontEnd : g_frontEnds) {
        if (frontEnd.nativePort == nativePort) {
            address.sin_addr.s_addr = htonl(kPlaceholderIp);
            address.sin_port = htons(frontEnd.guestPort);
            return true;
        }
    }
    return false;
}

bool WrapDatagram(NativeSocket native, const sockaddr_in& guestDest, const uint8_t* data, size_t size,
                  std::vector<uint8_t>& wrapped, sockaddr_in& nativeDest) {
    if (!Enabled()) {
        return false;
    }
    const uint32_t ip = ntohl(guestDest.sin_addr.s_addr);
    if (ip != kPlaceholderIp && !IsVirtualIp(ip)) {
        return false;
    }
    EnsureStarted();
    if (!g_state.ready) {
        return false;
    }
    if (g_state.mode == Mode::Client) {
        WaitForFirstCheck();
    }

    // The relay addresses replies by this socket's port, so it must have one
    // before the first datagram leaves.
    sockaddr_in local{};
    socklen_t length = sizeof(local);
    if (::getsockname(native, reinterpret_cast<sockaddr*>(&local), &length) != 0 || local.sin_port == 0) {
        sockaddr_in any{};
        any.sin_family = AF_INET;
        ::bind(native, reinterpret_cast<const sockaddr*>(&any), sizeof(any));
        length = sizeof(local);
        ::getsockname(native, reinterpret_cast<sockaddr*>(&local), &length);
    }

    wrapped.assign(kUdpMagic.begin(), kUdpMagic.end());
    PutU64(wrapped, g_state.clientId);
    PutU32(wrapped, 0);  // source IP: the relay knows ours
    PutU16(wrapped, ntohs(local.sin_port));
    PutU32(wrapped, ip);
    PutU16(wrapped, ntohs(guestDest.sin_port));
    wrapped.insert(wrapped.end(), data, data + size);
    nativeDest = g_state.relay;
    return true;
}

bool UnwrapDatagram(const sockaddr_in& nativeSource, std::vector<uint8_t>& datagram,
                    sockaddr_in& guestSource) {
    if (!Enabled() || !g_state.ready || !SameEndpoint(nativeSource, g_state.relay) ||
        datagram.size() < kDatagramHeaderSize ||
        !std::equal(kUdpMagic.begin(), kUdpMagic.end(), datagram.begin())) {
        return false;
    }
    guestSource = {};
    guestSource.sin_family = AF_INET;
    guestSource.sin_addr.s_addr = htonl(GetU32(datagram.data() + 12));
    guestSource.sin_port = htons(GetU16(datagram.data() + 16));
    datagram.erase(datagram.begin(), datagram.begin() + kDatagramHeaderSize);
    return true;
}

void Log(const char* format, ...) {
    char line[1024];
    std::va_list args;
    va_start(args, format);
    const int written = std::vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    if (written < 0) {
        return;
    }
    static const auto start = std::chrono::steady_clock::now();
    const double seconds =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    RT_LOGF(RT_TAG_NET, "direct: [%8.3f] %s\n", seconds, line);
    std::fflush(stderr);
}

SlowCallProbe::SlowCallProbe(const char* device, uint32_t cmd)
    : device_(device), cmd_(cmd), start_(std::chrono::steady_clock::now()) {}

SlowCallProbe::~SlowCallProbe() {
    constexpr auto kThreshold = std::chrono::milliseconds(100);
    const auto elapsed = std::chrono::steady_clock::now() - start_;
    if (elapsed >= kThreshold && Enabled()) {
        Log("slow %s cmd 0x%02X blocked the game thread for %lld ms", device_, cmd_,
            static_cast<long long>(
                std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()));
    }
}

void LogPayload(const char* label, const uint8_t* data, size_t size) {
    constexpr size_t kMaxShown = 600;
    std::string text;
    text.reserve(std::min(size, kMaxShown) * 2);
    for (size_t i = 0; i < size && i < kMaxShown; ++i) {
        const uint8_t byte = data[i];
        if (byte >= 0x20 && byte < 0x7F) {
            text.push_back(static_cast<char>(byte));
        } else if (byte == '\n') {
            text += "\\n";
        } else if (byte == '\r') {
            text += "\\r";
        } else {
            char escaped[5];
            std::snprintf(escaped, sizeof(escaped), "\\x%02X", byte);
            text += escaped;
        }
    }
    Log("%s: %zu bytes: %s%s", label, size, text.c_str(), size > kMaxShown ? "..." : "");
}

// DWC's control block pointer lives at _SDA_BASE_-0x6918 (DWCi_GetUserData,
// 0x800D0274) and holds the DWCAccUserData pointer at +0x1C. That struct is
// 0x40 bytes: size, pseudo and authentic login ids (u64 userid + u32 player id
// each), then gs_profile_id at +0x1C. The authentic userid's top bits are
// flags; the id itself is 43 bits.
StoredIdentity ReadStoredIdentity() {
    constexpr uint32_t kDwcControlPointer = 0x803862E8u;
    constexpr uint64_t kUserIdMask = (1ull << 43) - 1;
    if (!Memory::Contains(kDwcControlPointer, 4)) {
        return {};
    }
    const uint32_t control = Memory::Read32(kDwcControlPointer);
    if (!control || !Memory::Contains(control + 0x1C, 4)) {
        return {};
    }
    const uint32_t userData = Memory::Read32(control + 0x1C);
    if (!userData || !Memory::Contains(userData, 0x40) || Memory::Read32(userData) != 0x40) {
        return {};
    }
    const uint64_t userId =
        (static_cast<uint64_t>(Memory::Read32(userData + 0x10)) << 32) | Memory::Read32(userData + 0x14);
    return {userId & kUserIdMask, Memory::Read32(userData + 0x1C)};
}

namespace {
std::mutex g_knownPlayersMutex;
std::vector<uint32_t> g_knownPlayers;
std::atomic<uint64_t> g_knownPlayersGeneration{0};
}  // namespace

void SetKnownPlayers(std::vector<uint32_t> profileIds) {
    std::sort(profileIds.begin(), profileIds.end());
    std::lock_guard lock(g_knownPlayersMutex);
    if (profileIds != g_knownPlayers) {
        g_knownPlayers = std::move(profileIds);
        ++g_knownPlayersGeneration;
    }
}

uint64_t KnownPlayersGeneration() {
    return g_knownPlayersGeneration;
}

std::vector<uint32_t> KnownPlayers() {
    std::lock_guard lock(g_knownPlayersMutex);
    return g_knownPlayers;
}

namespace {
std::mutex g_loginMutex;
std::unordered_map<std::string, NasLogin> g_logins;
}  // namespace

void StoreNasLogin(const std::string& token, NasLogin login) {
    std::lock_guard lock(g_loginMutex);
    g_logins[token] = std::move(login);
}

std::optional<NasLogin> FindNasLogin(const std::string& token) {
    std::lock_guard lock(g_loginMutex);
    const auto it = g_logins.find(token);
    if (it == g_logins.end()) {
        return std::nullopt;
    }
    return it->second;
}

namespace {
constexpr std::string_view kDwcAlphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-";
constexpr char kDwcPadding = '*';
}  // namespace

std::string DwcBase64Encode(const uint8_t* data, size_t size) {
    std::string out;
    out.reserve((size + 2) / 3 * 4);
    for (size_t i = 0; i < size; i += 3) {
        const uint32_t remaining = static_cast<uint32_t>(std::min<size_t>(3, size - i));
        uint32_t group = static_cast<uint32_t>(data[i]) << 16;
        if (remaining > 1) group |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (remaining > 2) group |= data[i + 2];
        out.push_back(kDwcAlphabet[(group >> 18) & 63]);
        out.push_back(kDwcAlphabet[(group >> 12) & 63]);
        out.push_back(remaining > 1 ? kDwcAlphabet[(group >> 6) & 63] : kDwcPadding);
        out.push_back(remaining > 2 ? kDwcAlphabet[group & 63] : kDwcPadding);
    }
    return out;
}

std::optional<std::vector<uint8_t>> DwcBase64Decode(std::string_view text) {
    std::vector<uint8_t> out;
    uint32_t group = 0;
    int bits = 0;
    for (const char ch : text) {
        if (ch == kDwcPadding) {
            break;
        }
        const size_t value = kDwcAlphabet.find(ch);
        if (value == std::string_view::npos) {
            return std::nullopt;
        }
        group = (group << 6) | static_cast<uint32_t>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>(group >> bits));
        }
    }
    return out;
}

namespace {
std::mutex g_randomMutex;
std::mt19937_64& RandomEngine() {
    static std::mt19937_64 engine = [] {
        std::random_device device;
        return std::mt19937_64((static_cast<uint64_t>(device()) << 32) ^ device());
    }();
    return engine;
}
}  // namespace

uint64_t RandomU64() {
    std::lock_guard lock(g_randomMutex);
    return RandomEngine()();
}

std::string RandomUpper(size_t length) {
    std::string out(length, 'A');
    for (char& ch : out) {
        ch = static_cast<char>('A' + RandomU64() % 26);
    }
    return out;
}

}  // namespace NetworkHle::DirectOnline
