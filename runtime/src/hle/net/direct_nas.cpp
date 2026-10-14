// HTTP side of the built-in WFC server: NAS authentication (POST /ac, /pr) and
// the connection test. Protocol reference: WiiLink wfc-server, nas/account.go,
// nas/auth.go, nas/profanity.go and nas/conntest.go.

#include "direct_server.h"

#include <ctime>
#include <map>

namespace NetworkHle::DirectOnline {

namespace {

struct HttpRequest {
    std::string method;
    std::string path;
    std::string host;
    std::string soapAction;
    std::string body;
};

std::string Lowercase(std::string_view text) {
    return Lower(text);
}

std::string_view TrimSpaces(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) text.remove_suffix(1);
    return text;
}

// Pulls one complete request off the front of `buffer`. Returns nullopt while
// the headers or the Content-Length body are still incomplete.
std::optional<HttpRequest> TakeRequest(std::vector<uint8_t>& buffer) {
    const std::string_view data(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    const size_t headerEnd = data.find("\r\n\r\n");
    if (headerEnd == std::string_view::npos) {
        return std::nullopt;
    }

    HttpRequest request;
    size_t contentLength = 0;
    size_t lineStart = 0;
    bool firstLine = true;
    while (lineStart < headerEnd) {
        size_t lineEnd = data.find("\r\n", lineStart);
        if (lineEnd == std::string_view::npos || lineEnd > headerEnd) lineEnd = headerEnd;
        const std::string_view line = data.substr(lineStart, lineEnd - lineStart);
        if (firstLine) {
            const size_t methodEnd = line.find(' ');
            const size_t pathEnd = line.find(' ', methodEnd + 1);
            if (methodEnd != std::string_view::npos) {
                request.method = std::string(line.substr(0, methodEnd));
                request.path = std::string(line.substr(methodEnd + 1, pathEnd - methodEnd - 1));
            }
            firstLine = false;
        } else if (const size_t colon = line.find(':'); colon != std::string_view::npos) {
            const std::string name = Lowercase(TrimSpaces(line.substr(0, colon)));
            const std::string_view value = TrimSpaces(line.substr(colon + 1));
            if (name == "host") {
                request.host = Lowercase(value);
            } else if (name == "soapaction") {
                request.soapAction = std::string(value);
            } else if (name == "content-length") {
                std::from_chars(value.data(), value.data() + value.size(), contentLength);
            }
        }
        lineStart = lineEnd + 2;
    }

    const size_t total = headerEnd + 4 + contentLength;
    if (buffer.size() < total) {
        return std::nullopt;
    }
    request.body.assign(data.substr(headerEnd + 4, contentLength));
    buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(total));
    return request;
}

int HexValue(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

std::string UrlDecode(std::string_view text) {
    std::string out;
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '%' && i + 2 < text.size() && HexValue(text[i + 1]) >= 0 &&
            HexValue(text[i + 2]) >= 0) {
            out.push_back(static_cast<char>(HexValue(text[i + 1]) * 16 + HexValue(text[i + 2])));
            i += 2;
        } else if (text[i] == '+') {
            out.push_back(' ');
        } else {
            out.push_back(text[i]);
        }
    }
    return out;
}

// Form fields with their DWC-base64 values already decoded. Keys starting with
// '_' are CTGP/Wiimmfi payload extras and are dropped, as wfc-server does.
std::optional<std::map<std::string, std::vector<uint8_t>>> ParseAuthForm(std::string_view body) {
    std::map<std::string, std::vector<uint8_t>> fields;
    // DWC NUL-terminates the body like it does the response.
    while (!body.empty() && body.back() == '\0') body.remove_suffix(1);
    size_t start = 0;
    while (start <= body.size()) {
        size_t end = body.find('&', start);
        if (end == std::string_view::npos) end = body.size();
        const std::string_view pair = body.substr(start, end - start);
        if (const size_t equals = pair.find('='); equals != std::string_view::npos) {
            const std::string key = UrlDecode(pair.substr(0, equals));
            if (!key.empty() && key[0] != '_') {
                auto value = DwcBase64Decode(UrlDecode(pair.substr(equals + 1)));
                if (!value) {
                    Log("nas: field '%s' is not valid DWC base64", key.c_str());
                    return std::nullopt;
                }
                fields[key] = std::move(*value);
            }
        }
        start = end + 1;
    }
    return fields;
}

std::string FieldText(const std::map<std::string, std::vector<uint8_t>>& fields, const char* key) {
    const auto it = fields.find(key);
    return it == fields.end() ? std::string() : std::string(it->second.begin(), it->second.end());
}

std::string DateTimeUtc() {
    const std::time_t now = std::time(nullptr);
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &now);
#else
    gmtime_r(&now, &utc);
#endif
    char text[16];
    std::strftime(text, sizeof(text), "%Y%m%d%H%M%S", &utc);
    return text;
}

// key=dwcbase64(value)&..., sorted by key like Go's url.Values.Encode, then
// NUL-terminated: DWC parses the reply as a C string. The DWC alphabet needs no
// URL escaping.
std::string FormatAuthReply(const std::map<std::string, std::string>& reply) {
    std::string body;
    for (const auto& [key, value] : reply) {
        if (!body.empty()) body.push_back('&');
        body += key;
        body.push_back('=');
        body += DwcBase64Encode(reinterpret_cast<const uint8_t*>(value.data()), value.size());
    }
    body.push_back('\0');
    return body;
}

// Every response closes the connection. The SSL HLE serves these hosts as
// plain TCP with blocking reads on the emulation thread, so a client still
// reading a kept-alive connection would stall the game until the read timeout.
void SendResponse(TcpLink& link, int status, const char* reason, const char* contentType,
                  std::string_view body, std::string_view extraHeaders = {}) {
    std::string response = "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\n";
    response += "Content-Type: ";
    response += contentType;
    response += "\r\nContent-Length: " + std::to_string(body.size()) + "\r\n";
    response += extraHeaders;
    response += "Connection: close\r\nServer: Nintendo\r\n\r\n";
    response += body;
    link.Send(response);
    link.Close();
}

std::map<std::string, std::string> AccountCreate() {
    // wfc-server: database.GetUniqueUserID, a random id below 0x80000000000.
    const uint64_t userId = RandomU64() % 0x80000000000ull;
    return {
        {"retry", "0"},
        {"datetime", DateTimeUtc()},
        {"returncd", "002"},
        {"userid", std::to_string(userId)},
    };
}

std::map<std::string, std::string> Login(const std::map<std::string, std::vector<uint8_t>>& fields) {
    std::map<std::string, std::string> reply = {
        {"retry", "0"},
        {"datetime", DateTimeUtc()},
        {"locator", "gamespy.com"},
    };

    NasLogin login;
    login.gameCode = FieldText(fields, "gamecd");
    login.gsbrCode = FieldText(fields, "gsbrcd");
    const std::string userId = FieldText(fields, "userid");
    const std::string cfc = FieldText(fields, "cfc");
    std::from_chars(userId.data(), userId.data() + userId.size(), login.userId);
    std::from_chars(cfc.data(), cfc.data() + cfc.size(), login.consoleFriendCode);
    if (const auto it = fields.find("ingamesn"); it != fields.end()) {
        login.inGameName = it->second;
    }
    if (login.gameCode.size() < 4 || userId.empty() || login.userId >= 0x80000000000ull) {
        Log("nas: login rejected (gamecd='%s' userid='%s')", login.gameCode.c_str(), userId.c_str());
        reply["returncd"] = "103";
        return reply;
    }
    if (login.gsbrCode.empty()) {
        login.gsbrCode = login.gameCode.substr(0, 3) + "J";
    }

    std::array<uint8_t, 96> tokenBytes{};
    for (size_t i = 0; i < tokenBytes.size(); i += 8) {
        const uint64_t value = RandomU64();
        std::memcpy(tokenBytes.data() + i, &value, 8);
    }
    const std::string token = "NDS" + DwcBase64Encode(tokenBytes.data(), tokenBytes.size());
    login.challenge = RandomUpper(8);

    Log("nas: login userid=%" PRIu64 " gamecd=%s gsbrcd=%s cfc=%" PRIu64, login.userId,
        login.gameCode.c_str(), login.gsbrCode.c_str(), login.consoleFriendCode);
    reply["returncd"] = "001";
    reply["challenge"] = login.challenge;
    reply["token"] = token;
    StoreNasLogin(token, std::move(login));
    return reply;
}

std::map<std::string, std::string> ServiceLocation(const std::map<std::string, std::vector<uint8_t>>& fields) {
    std::map<std::string, std::string> reply = {
        {"retry", "0"},
        {"datetime", DateTimeUtc()},
        {"returncd", "007"},
        {"statusdata", "Y"},
    };
    const std::string service = FieldText(fields, "svc");
    if (service == "9000") {
        reply["token"] = "NDS/SVCLOC/TOKEN";
        reply["svchost"] = "dls1.nintendowifi.net";
    } else {
        reply["servicetoken"] = "NDS/SVCLOC/TOKEN";
        reply["svchost"] = service == "9001" ? "dls1.nintendowifi.net" : "n/a";
    }
    return reply;
}

// No word filter: report every word as clean. `words` is tab-separated, in
// UTF-16 (BE on Wii) unless `wenc` says UTF-8.
std::map<std::string, std::string> ProfanityCheck(const std::map<std::string, std::vector<uint8_t>>& fields) {
    const auto it = fields.find("words");
    const std::vector<uint8_t> words = it == fields.end() ? std::vector<uint8_t>() : it->second;
    const bool utf8 = FieldText(fields, "wenc") == "UTF-8";
    size_t count = 1;
    if (utf8) {
        count += static_cast<size_t>(std::count(words.begin(), words.end(), '\t'));
    } else {
        for (size_t i = 0; i + 1 < words.size(); i += 2) {
            if ((words[i] == 0 && words[i + 1] == '\t') || (words[i] == '\t' && words[i + 1] == 0)) {
                ++count;
            }
        }
    }
    const std::string clean(count, '0');
    std::map<std::string, std::string> reply = {{"returncd", "000"}, {"prwords", clean}};
    if (FieldText(fields, "wregion") == "A") {
        for (const char* region : {"A", "C", "E", "J", "K", "P"}) {
            reply[std::string("prwords") + region] = clean;
        }
    }
    return reply;
}

constexpr std::string_view kConnTestPage =
    "\n"
    "            <!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" "
    "\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n"
    "            <html>\n"
    "            <head>\n"
    "            <title>HTML Page</title>\n"
    "            </head>\n"
    "            <body bgcolor=\"#FFFFFF\">\n"
    "            This is test.html page\n"
    "            </body>\n"
    "            </html>\n"
    "          ";

// The text of every element named `name` in `xml`, whatever its namespace
// prefix (<ns1:tableid>, <tableid>). Enough for sake's flat SOAP requests.
std::vector<std::string> ElementTexts(std::string_view xml, std::string_view name) {
    std::vector<std::string> texts;
    size_t position = 0;
    while ((position = xml.find('<', position)) != std::string_view::npos) {
        const size_t nameEnd = xml.find_first_of(" />", position + 1);
        if (nameEnd == std::string_view::npos) break;
        const std::string_view fullTag = xml.substr(position + 1, nameEnd - position - 1);
        std::string_view tag = fullTag;
        if (const size_t colon = tag.find(':'); colon != std::string_view::npos) tag.remove_prefix(colon + 1);
        const size_t open = xml.find('>', position);
        if (open == std::string_view::npos) break;
        if (tag == name && xml[open - 1] != '/') {
            const size_t close = xml.find("</" + std::string(fullTag) + ">", open);
            if (close == std::string_view::npos) break;
            texts.emplace_back(xml.substr(open + 1, close - open - 1));
        }
        position = open + 1;
    }
    return texts;
}

// Decodes XML character references and the predefined entities: the game
// writes the sake filter as "ownerid&#x20;=&#x20;N".
std::string XmlUnescape(std::string_view text) {
    std::string out;
    for (size_t i = 0; i < text.size(); ++i) {
        const size_t end = text[i] == '&' ? text.find(';', i) : std::string_view::npos;
        if (end == std::string_view::npos) {
            out.push_back(text[i]);
            continue;
        }
        const std::string_view entity = text.substr(i + 1, end - i - 1);
        uint32_t code = 0;
        if (entity == "amp") code = '&';
        else if (entity == "lt") code = '<';
        else if (entity == "gt") code = '>';
        else if (entity == "quot") code = '"';
        else if (entity == "apos") code = '\'';
        else if (entity.size() > 2 && entity[0] == '#' && (entity[1] == 'x' || entity[1] == 'X'))
            std::from_chars(entity.data() + 2, entity.data() + entity.size(), code, 16);
        else if (entity.size() > 1 && entity[0] == '#')
            std::from_chars(entity.data() + 1, entity.data() + entity.size(), code);
        if (code == 0 || code > 0x7F) {
            out.push_back(text[i]);  // not one we decode; keep it as written
            continue;
        }
        out.push_back(static_cast<char>(code));
        i = end;
    }
    return out;
}

std::string ElementText(std::string_view xml, std::string_view name) {
    auto texts = ElementTexts(xml, name);
    return texts.empty() ? std::string() : XmlUnescape(texts.front());
}

// MKWii's FriendInfo table: one record per player holding "info", a 96-byte
// binary blob (Mii, Wii number, region, location) that the game uploads after
// login (0x8067805C) and that friends fetch with SearchForRecords
// "ownerid = N" (0x806742D4) to fill in that friend's Mii. Kept in memory for
// the host's lifetime; the game re-creates its record on every login.
struct FriendInfoRecord {
    int32_t recordId = 0;
    std::string info;  // base64, exactly as the game sent it
};
std::map<uint32_t, FriendInfoRecord> g_friendInfo;
int32_t g_nextRecordId = 1;

// One record's values in the order the request's <fields> asks for them.
std::string FriendInfoValues(const FriendInfoRecord& record, uint32_t ownerId,
                             const std::vector<std::string>& fields) {
    std::string values = "<ArrayOfRecordValue>";
    for (const std::string& field : fields) {
        if (field == "info") {
            values += "<RecordValue><binaryDataValue>" + record.info + "</binaryDataValue></RecordValue>";
        } else if (field == "recordid") {
            values += "<RecordValue><intValue>" + std::to_string(record.recordId) + "</intValue></RecordValue>";
        } else if (field == "ownerid") {
            values += "<RecordValue><intValue>" + std::to_string(static_cast<int32_t>(ownerId)) +
                "</intValue></RecordValue>";
        } else {
            return {};  // wfc-server drops a record missing a requested field
        }
    }
    return values + "</ArrayOfRecordValue>";
}

// Sake (GameSpy storage, SOAP over HTTP). FriendInfo is stored as above;
// every other table succeeds with no records, and its writes are dropped.
// Response shapes follow wfc-server sake/storage.go.
std::string SakeResponse(const HttpRequest& request) {
    std::string action = request.soapAction;
    action.erase(std::remove(action.begin(), action.end(), '"'), action.end());
    const std::string operation = action.substr(action.rfind('/') + 1);
    const std::string table = ElementText(request.body, "tableid");
    const std::vector<std::string> fields = ElementTexts(ElementText(request.body, "fields"), "string");
    const auto owner = ProfileForLoginTicket(ElementText(request.body, "loginTicket"));

    std::string inner;
    std::string values;
    std::string note = "no data";
    if (table == "FriendInfo" && owner) {
        if (operation == "CreateRecord" || operation == "UpdateRecord") {
            FriendInfoRecord& record = g_friendInfo[*owner];
            if (record.recordId == 0) record.recordId = g_nextRecordId++;
            record.info = ElementText(request.body, "binaryDataValue");
            if (operation == "CreateRecord") {
                inner = "<recordid>" + std::to_string(record.recordId) + "</recordid>";
            }
            note = "stored " + std::to_string(record.info.size()) + " base64 chars for " + std::to_string(*owner);
        } else if (operation == "GetMyRecords") {
            if (const auto it = g_friendInfo.find(*owner); it != g_friendInfo.end()) {
                values = FriendInfoValues(it->second, *owner, fields);
                note = "own record";
            }
        } else if (operation == "SearchForRecords") {
            // The game's only search here is "ownerid = N".
            const std::string filter = ElementText(request.body, "filter");
            uint32_t ownerId = 0;
            if (const size_t at = filter.find("ownerid"); at != std::string::npos) {
                const size_t digits = filter.find_first_of("0123456789", at);
                if (digits != std::string::npos) {
                    std::from_chars(filter.data() + digits, filter.data() + filter.size(), ownerId);
                }
            }
            if (const auto it = g_friendInfo.find(ownerId); it != g_friendInfo.end()) {
                values = FriendInfoValues(it->second, ownerId, fields);
                note = "record of " + std::to_string(ownerId);
            } else {
                note = "no record for '" + filter + "'";
            }
        }
    } else if (operation == "CreateRecord") {
        inner = "<recordid>1</recordid>";
    }
    if (operation == "GetMyRecords" || operation == "SearchForRecords" ||
        operation == "GetSpecificRecords" || operation == "GetRandomRecords") {
        inner = "<values>" + values + "</values>";
    }
    Log("sake: %s %s -> Success (%s)", operation.c_str(), table.c_str(), note.c_str());
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
           "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>"
           "<" + operation + "Response xmlns=\"http://gamespy.net/sake\">"
           "<" + operation + "Result>Success</" + operation + "Result>" + inner +
           "</" + operation + "Response></s:Body></s:Envelope>";
}

bool IsSakeStorageRequest(const HttpRequest& request, std::string_view path) {
    return request.method == "POST" && request.host.find(".sake.") != std::string::npos &&
        path == "/SakeStorageServer/StorageServer.asmx" && !request.soapAction.empty();
}

bool IsNasHost(std::string_view host) {
    return host.rfind("nas.", 0) == 0 || host.rfind("naswii.", 0) == 0;
}

class HttpSession final : public TcpSession {
public:
    void OnData(TcpLink& link, std::vector<uint8_t>& buffer) override {
        // One request per connection; see SendResponse.
        if (auto request = TakeRequest(buffer)) {
            Handle(link, *request);
        }
    }

private:
    static void Handle(TcpLink& link, const HttpRequest& request) {
        Log("%s %s %s%s", link.Label().c_str(), request.method.c_str(), request.host.c_str(),
            request.path.c_str());

        const std::string path = request.path.substr(0, request.path.find('?'));
        if (request.method == "POST" && IsNasHost(request.host) && (path == "/ac" || path == "/pr")) {
            const auto fields = ParseAuthForm(request.body);
            if (!fields) {
                SendResponse(link, 400, "Bad Request", "text/html", "400 Bad Request");
                return;
            }
            const std::string action = Lowercase(FieldText(*fields, "action"));
            std::map<std::string, std::string> reply;
            if (path == "/pr") {
                reply = ProfanityCheck(*fields);
            } else if (action == "acctcreate") {
                reply = AccountCreate();
            } else if (action == "login") {
                reply = Login(*fields);
            } else if (action == "svcloc") {
                reply = ServiceLocation(*fields);
            } else {
                Log("nas: unknown action '%s'", action.c_str());
                SendResponse(link, 400, "Bad Request", "text/html", "400 Bad Request");
                return;
            }
            Log("nas: %s -> returncd=%s", path == "/pr" ? "pr" : action.c_str(),
                reply.count("returncd") ? reply["returncd"].c_str() : "?");
            SendResponse(link, 200, "OK", "text/plain", FormatAuthReply(reply));
            return;
        }

        if (IsSakeStorageRequest(request, path)) {
            SendResponse(link, 200, "OK", "text/xml", SakeResponse(request));
            return;
        }

        if (request.method == "GET" && request.host.rfind("conntest.", 0) == 0) {
            SendResponse(link, 200, "OK", "text/html", kConnTestPage,
                         "X-Organization: Nintendo\r\n");
            return;
        }

        if (!request.body.empty()) {
            LogPayload("http: unhandled request body",
                       reinterpret_cast<const uint8_t*>(request.body.data()), request.body.size());
        }
        SendResponse(link, 404, "Not Found", "text/html", "404 Not Found");
    }
};

}  // namespace

std::unique_ptr<TcpSession> CreateHttpSession() {
    return std::make_unique<HttpSession>();
}

}  // namespace NetworkHle::DirectOnline
