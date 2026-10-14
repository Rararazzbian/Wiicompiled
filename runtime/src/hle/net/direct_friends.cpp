// Puts the players on the host into the current license's friend list, the
// way the game's own "Register Friend Code" screen does, so they show up in
// the Friends menu. Runs on the emulation thread: just before the game logs
// in to GPCM, and whenever the host's player list changes while online. DWC
// sends a buddy request for each new entry (at login, or after
// RKNet::Controller::UpdateServersAsync), and the host's GPCM, where everyone
// is an "open host", makes them mutual friends.
//
// Guest layout (PAL), from the translated code:
// - SaveManager* at 0x809BD748: current license index s16 at +0x36; licenses
//   (LicenseMgr, 0x93F0 bytes each) from +0x38.
// - LicenseMgr+0x59D0: 30 raw friend entries of 0x1C0 bytes (Friend::AddFriend
//   0x80519704 fills one); +0x8E50: DWCFriendData[30], index-aligned with
//   them; +0x8FB8: DWCUserData (game id at +0x24).
// - RKNet::FriendMgr* at 0x809C2110: the DWCFriendData[30] DWC uses at +0x9C,
//   and its committed copy at +0x204 (FriendMgr::Update 0x80663444).
// - SectionMgr* at 0x809C1E38: current Section at +0, its FriendList* at
//   +0x404 (null when the section has none; 30 entries of 0x1D8 bytes: code
//   u64, Friend at +8 with the raw entry at +0x10, status s32 at +0x1D0); the
//   save requester* at +0x90, whose byte +0x16 asks for a save
//   (NotifyNewLicenseContent 0x80621410).

#include "direct_server.h"

#include "guest_interrupt_context.h"

#include <algorithm>
#include <chrono>
#include <map>
#include <set>

namespace NetworkHle::DirectOnline {

namespace {

constexpr uint32_t kSaveManagerPointer = 0x809BD748u;
constexpr uint32_t kCurrentLicenseOffset = 0x36;
constexpr uint32_t kLicensesOffset = 0x38;
constexpr uint32_t kLicenseSize = 0x93F0;
constexpr uint32_t kRawFriendsOffset = 0x59D0;
constexpr uint32_t kRawFriendSize = 0x1C0;
constexpr uint32_t kDwcFriendsOffset = 0x8E50;
constexpr uint32_t kUserDataOffset = 0x8FB8;
constexpr uint32_t kFriendMgrPointer = 0x809C2110u;
constexpr uint32_t kFriendMgrLiveFriends = 0x9C;
constexpr uint32_t kFriendMgrCommittedFriends = 0x204;
constexpr uint32_t kSectionMgrPointer = 0x809C1E38u;
constexpr uint32_t kSectionFriendList = 0x404;
constexpr uint32_t kSectionMgrSaveRequester = 0x90;
constexpr uint32_t kFriendListEntrySize = 0x1D8;
constexpr uint32_t kFriendListRawOffset = 0x10;
constexpr uint32_t kFriendListStatusOffset = 0x1D0;
// FriendCodesController (FriendList+0x3750) copies the entries' codes to
// u64[30] at FriendList+0x3760 and hands FriendMgr that array; FriendMgr
// keeps it at +0x3E4 until it can process it.
constexpr uint32_t kFriendListCodeSnapshot = 0x3760;
constexpr uint32_t kFriendMgrPendingCodes = 0x3E4;
constexpr int kMaxFriends = 30;
constexpr uint32_t kDwcFriendDataSize = 12;
// DWCFriendData word 0: type in bits 11-12; 2 = friend key (+4 pid, +8
// checksum), as DWC::CreateFriendKeyToken (0x800EC764) writes it.
constexpr uint32_t kDwcTypeMask = 0x1800;
constexpr uint32_t kDwcFriendKey = 0x1000;
// DWC's friend control block (_SDA_BASE_-0x6930); DWC::CanChangeFriendList
// (0x800CE2E4) refuses changes while its state byte at +0x22 is 1 or 2.
uint32_t ReadPointer(uint32_t address);

constexpr uint32_t kDwcFriendControlPointer = 0x803862D0u;
constexpr uint32_t kRkNetControllerPointer = 0x809C20D8u;
constexpr uint32_t kCanExchangeFriendData = 0x80656D9Cu;  // (Controller*) -> bool
constexpr uint32_t kUpdateServersAsync = 0x80656B44u;     // (Controller*)

bool CanChangeFriendList() {
    const uint32_t control = ReadPointer(kDwcFriendControlPointer);
    if (!control) {
        return true;
    }
    const uint8_t state = Memory::Read8(control + 0x22);
    return state != 1 && state != 2;
}

// FriendMgr::Update's ending (0x80663548): when DWC is online and can
// exchange friend data, have it send buddy requests for the new entries.
// DWCi_UpdateServersAsync only queues the work, so this is safe from inside
// a network call.
void RequestFriendUpdate() {
    const uint32_t controller = ReadPointer(kRkNetControllerPointer);
    if (!controller) {
        return;
    }
    GuestInterruptCallbackContext interrupt;
    CpuContext* cpu = interrupt.get();
    cpu->gpr[3] = controller;
    InvokeIndirectCpu(kCanExchangeFriendData, cpu);
    if (cpu->gpr[3] == 0) {
        return;
    }
    cpu->gpr[3] = controller;
    InvokeIndirectCpu(kUpdateServersAsync, cpu);
    Log("friends: asked DWC to send buddy requests");
}

uint32_t ReadPointer(uint32_t address) {
    if (!Memory::Contains(address, 4)) {
        return 0;
    }
    const uint32_t value = Memory::Read32(address);
    return value && Memory::Contains(value, 4) ? value : 0;
}

uint64_t Read64(uint32_t address) {
    return (static_cast<uint64_t>(Memory::Read32(address)) << 32) | Memory::Read32(address + 4);
}

void Write64(uint32_t address, uint64_t value) {
    Memory::Write32(address, static_cast<uint32_t>(value >> 32));
    Memory::Write32(address + 4, static_cast<uint32_t>(value));
}

void Zero(uint32_t address, uint32_t size) {
    for (uint32_t offset = 0; offset < size; offset += 4) {
        Memory::Write32(address + offset, 0);
    }
}

// The raw entry Friend::AddFriend (0x80519704) makes: the code, flags 3
// (in use, not yet seen online), VR and BR 5000, and the slot index.
void WriteRawFriend(uint32_t entry, uint64_t code, int slot) {
    Zero(entry, kRawFriendSize);
    Write64(entry, code);
    Memory::Write16(entry + 0x10, 3);
    Memory::Write16(entry + 0x16, 5000);
    Memory::Write16(entry + 0x18, 5000);
    Memory::Write8(entry + 0x66, static_cast<uint8_t>(slot));
}

void WriteDwcFriendKey(uint32_t entry, uint64_t code) {
    Memory::Write32(entry, kDwcFriendKey);
    Memory::Write32(entry + 4, static_cast<uint32_t>(code));
    Memory::Write32(entry + 8, static_cast<uint32_t>(code >> 32));
}

// NotifyNewLicenseContent (0x80621410): ask for a save unless one is
// already under way.
void RequestSave(uint32_t sectionMgr) {
    const uint32_t requester = sectionMgr ? ReadPointer(sectionMgr + kSectionMgrSaveRequester) : 0;
    if (requester && Memory::Read8(requester + 0x14) == 0 && Memory::Read8(requester + 0x02) == 0) {
        Memory::Write8(requester + 0x16, 1);
    }
}

// Returns false when the friend list can't be changed yet (try again later).
bool AddPlayers(const std::vector<uint32_t>& players, bool loggingIn) {
    if (players.empty()) {
        return true;
    }
    if (!CanChangeFriendList()) {
        return false;
    }
    const uint32_t saveManager = ReadPointer(kSaveManagerPointer);
    if (!saveManager) {
        return true;
    }
    const auto licenseIndex = static_cast<int16_t>(Memory::Read16(saveManager + kCurrentLicenseOffset));
    if (licenseIndex < 0 || licenseIndex >= 4) {
        return true;
    }
    const uint32_t license = saveManager + kLicensesOffset + static_cast<uint32_t>(licenseIndex) * kLicenseSize;
    const uint32_t userData = license + kUserDataOffset;
    const uint32_t ownProfileId = Memory::Read32(userData + 0x1C);
    const uint32_t gameIdWord = Memory::Read32(userData + 0x24);
    const char gameId[4] = {static_cast<char>(gameIdWord >> 24), static_cast<char>(gameIdWord >> 16),
                            static_cast<char>(gameIdWord >> 8), static_cast<char>(gameIdWord)};

    const uint32_t friendMgr = ReadPointer(kFriendMgrPointer);
    const uint32_t sectionMgr = ReadPointer(kSectionMgrPointer);
    const uint32_t section = sectionMgr ? ReadPointer(sectionMgr) : 0;
    const uint32_t friendList = section ? ReadPointer(section + kSectionFriendList) : 0;

    std::set<uint32_t> listed;
    for (int slot = 0; slot < kMaxFriends; ++slot) {
        const uint64_t code = Read64(license + kRawFriendsOffset + slot * kRawFriendSize);
        if (code != 0) {
            listed.insert(static_cast<uint32_t>(code));
        }
    }

    int added = 0;
    for (const uint32_t profileId : players) {
        if (profileId == 0 || profileId == ownProfileId || listed.count(profileId)) {
            continue;
        }
        // The first slot that is free in the license, in DWC's list and in an
        // open FriendList alike: FriendMgr::Update deletes a DWC entry whose
        // roster slot is empty, so the indexes must line up.
        int slot = -1;
        for (int i = 0; i < kMaxFriends && slot < 0; ++i) {
            const bool rawFree = Read64(license + kRawFriendsOffset + i * kRawFriendSize) == 0;
            const bool dwcFree = (Memory::Read32(license + kDwcFriendsOffset + i * kDwcFriendDataSize) & kDwcTypeMask) == 0;
            const bool liveFree = !friendMgr ||
                (Memory::Read32(friendMgr + kFriendMgrLiveFriends + i * kDwcFriendDataSize) & kDwcTypeMask) == 0;
            const bool listFree = !friendList || Read64(friendList + i * kFriendListEntrySize) == 0;
            if (rawFree && dwcFree && liveFree && listFree) {
                slot = i;
            }
        }
        if (slot < 0) {
            Log("friends: no free friend slot for profile %u", profileId);
            break;
        }

        const uint64_t code = FriendKey(profileId, std::string_view(gameId, 4));
        WriteRawFriend(license + kRawFriendsOffset + slot * kRawFriendSize, code, slot);
        WriteDwcFriendKey(license + kDwcFriendsOffset + slot * kDwcFriendDataSize, code);
        if (friendMgr) {
            WriteDwcFriendKey(friendMgr + kFriendMgrLiveFriends + slot * kDwcFriendDataSize, code);
            WriteDwcFriendKey(friendMgr + kFriendMgrCommittedFriends + slot * kDwcFriendDataSize, code);
        }
        if (friendList) {
            const uint32_t entry = friendList + slot * kFriendListEntrySize;
            Write64(entry, code);
            WriteRawFriend(entry + kFriendListRawOffset, code, slot);
            Memory::Write32(entry + kFriendListStatusOffset, 0);
            // FriendCodesController's snapshot of the codes. FriendMgr::Update
            // deletes every DWC entry whose code there is 0.
            Write64(friendList + kFriendListCodeSnapshot + slot * 8, code);
        }
        if (friendMgr) {
            // A snapshot FriendMgr hasn't processed yet (it waits while DWC
            // can't change the list): same deletion rule.
            if (const uint32_t pending = ReadPointer(friendMgr + kFriendMgrPendingCodes)) {
                Write64(pending + slot * 8, code);
            }
        }
        listed.insert(profileId);
        ++added;
        Log("friends: added profile %u (friend code %04llu-%04llu-%04llu) in slot %d", profileId,
            static_cast<unsigned long long>(code / 100000000ull),
            static_cast<unsigned long long>(code / 10000ull % 10000ull),
            static_cast<unsigned long long>(code % 10000ull), slot);
    }

    if (added > 0) {
        RequestSave(sectionMgr);
    }
    if (added > 0 && !loggingIn) {
        RequestFriendUpdate();
    }
    return true;
}

// Takes a player who left the host off the friend list, as deleting a
// friend does: the license entries are cleared, and the open FriendList's
// entry and code snapshot too, after which FriendMgr::Update (0x80663444)
// sees code 0 for a valid DWC slot and deletes it properly
// (DeleteBuddyFriendData: \delbuddy\ to the server). Without an open
// FriendList, DWC's own copies are cleared directly. Returns false when the
// friend list can't be changed yet.
bool RemovePlayer(uint32_t profileId) {
    if (!CanChangeFriendList()) {
        return false;
    }
    const uint32_t saveManager = ReadPointer(kSaveManagerPointer);
    if (!saveManager) {
        return true;
    }
    const auto licenseIndex = static_cast<int16_t>(Memory::Read16(saveManager + kCurrentLicenseOffset));
    if (licenseIndex < 0 || licenseIndex >= 4) {
        return true;
    }
    const uint32_t license = saveManager + kLicensesOffset + static_cast<uint32_t>(licenseIndex) * kLicenseSize;
    int slot = -1;
    for (int i = 0; i < kMaxFriends && slot < 0; ++i) {
        const uint64_t code = Read64(license + kRawFriendsOffset + i * kRawFriendSize);
        if (code != 0 && static_cast<uint32_t>(code) == profileId) {
            slot = i;
        }
    }
    if (slot < 0) {
        return true;
    }

    const uint32_t friendMgr = ReadPointer(kFriendMgrPointer);
    const uint32_t sectionMgr = ReadPointer(kSectionMgrPointer);
    const uint32_t section = sectionMgr ? ReadPointer(sectionMgr) : 0;
    const uint32_t friendList = section ? ReadPointer(section + kSectionFriendList) : 0;

    Zero(license + kRawFriendsOffset + slot * kRawFriendSize, kRawFriendSize);
    Zero(license + kDwcFriendsOffset + slot * kDwcFriendDataSize, kDwcFriendDataSize);
    if (friendList) {
        const uint32_t entry = friendList + slot * kFriendListEntrySize;
        Write64(entry, 0);
        Zero(entry + kFriendListRawOffset, kRawFriendSize);
        Memory::Write32(entry + kFriendListStatusOffset, static_cast<uint32_t>(-1));
        Write64(friendList + kFriendListCodeSnapshot + slot * 8, 0);
    }
    if (friendMgr) {
        if (const uint32_t pending = ReadPointer(friendMgr + kFriendMgrPendingCodes)) {
            Write64(pending + slot * 8, 0);
        } else if (friendList) {
            // Have FriendMgr::Update apply the snapshot (FriendMgr::
            // SetCodesForUnusedIdxs stores it the same way).
            Memory::Write32(friendMgr + kFriendMgrPendingCodes, friendList + kFriendListCodeSnapshot);
        }
        if (!friendList) {
            Zero(friendMgr + kFriendMgrLiveFriends + slot * kDwcFriendDataSize, kDwcFriendDataSize);
            Zero(friendMgr + kFriendMgrCommittedFriends + slot * kDwcFriendDataSize, kDwcFriendDataSize);
        }
    }
    RequestSave(sectionMgr);
    Log("friends: removed profile %u (left the host) from slot %d", profileId, slot);
    return true;
}

// The KnownPlayers() generation last added to the friend list.
uint64_t g_appliedGeneration = 0;

// Players seen on the host this session, and since when each one that is
// gone has been gone. Only those are ever removed: friends from anywhere
// else stay. A player is removed after being gone this long, so a game
// reconnecting (after a race, or between menus) keeps its place.
std::set<uint32_t> g_seenPlayers;
std::map<uint32_t, std::chrono::steady_clock::time_point> g_goneSince;
constexpr auto kRemoveAfter = std::chrono::seconds(15);

void TrackDepartures(const std::vector<uint32_t>& players) {
    const auto now = std::chrono::steady_clock::now();
    for (const uint32_t profileId : players) {
        g_seenPlayers.insert(profileId);
        g_goneSince.erase(profileId);
    }
    for (const uint32_t profileId : g_seenPlayers) {
        if (std::find(players.begin(), players.end(), profileId) == players.end()) {
            g_goneSince.emplace(profileId, now);
        }
    }
    for (auto it = g_goneSince.begin(); it != g_goneSince.end();) {
        if (now - it->second >= kRemoveAfter && RemovePlayer(it->first)) {
            g_seenPlayers.erase(it->first);
            it = g_goneSince.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace

void AddKnownPlayersBeforeLogin() {
    const uint64_t generation = KnownPlayersGeneration();
    if (AddPlayers(KnownPlayers(), true)) {
        g_appliedGeneration = generation;
    }
}

void FriendListTick() {
    const uint64_t generation = KnownPlayersGeneration();
    if (generation != g_appliedGeneration || !g_goneSince.empty()) {
        const std::vector<uint32_t> players = KnownPlayers();
        if (generation != g_appliedGeneration && AddPlayers(players, false)) {
            g_appliedGeneration = generation;
        }
        TrackDepartures(players);
    }
}

}  // namespace NetworkHle::DirectOnline
