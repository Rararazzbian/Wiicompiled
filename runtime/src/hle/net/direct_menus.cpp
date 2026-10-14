// Online menu changes for direct-connect online. Each wraps the translated
// game function (still callable as func_XXXXXXXX) and only differs in direct
// mode:
// - Connecting to WFC lands on the Friends screen instead of the WFC main
//   menu (Worldwide / Continental / Friends): everyone on a direct host is a
//   friend, so the other options have no use.
// - Back on that Friends screen leaves online, as the main menu's Back does,
//   instead of returning to the menu that is no longer shown.
// - The Friend Roster re-lays out its tiles when a player joins the host while
//   it is open (the game only lays them out when the page activates).
//
// Page ids and layouts (PAL), from the translated code: the current Section
// is *(SectionMgr* at 0x809C1E38); a page's id is at +4, its state at +8 (4 =
// active) and the page it goes to next at +0xF30. Page 139 is WFCMainMenu,
// 141 the Friends screen its Friends button opens (WFCFriendsMenu; Back goes
// to 139), 142 the root variant of that screen (Back asks to disconnect, page
// 135), 150 the Friend Roster (Pages::FriendList).

#include "direct_server.h"

#include "abi_bridge.h"

extern "C" void func_806478C4(CpuContext* ctx);
extern "C" void func_8064D4F4(CpuContext* ctx);
extern "C" void func_8064D60C(CpuContext* ctx);
extern "C" void func_805D4C10(CpuContext* ctx);
extern "C" void func_8064CA98(CpuContext* ctx);
extern "C" void func_805E46C8(CpuContext* ctx);

namespace NetworkHle::DirectOnline {

namespace {

constexpr uint32_t kMenuSectionMgrPointer = 0x809C1E38u;
constexpr uint32_t kMenuSectionFriendList = 0x404;
constexpr uint32_t kMenuFriendEntrySize = 0x1D8;
constexpr int kMenuMaxFriends = 30;
constexpr uint32_t kPageId = 0x04;
constexpr uint32_t kPageState = 0x08;
constexpr uint32_t kPageStateActive = 4;
constexpr uint32_t kMenuNextPage = 0xF30;
constexpr uint32_t kPageWfcMainMenu = 139;
constexpr uint32_t kPageFriends = 141;
constexpr uint32_t kPageDisconnectPrompt = 135;
constexpr uint32_t kPushPageVirtual = 0x24;  // (page, pageId, animation)
constexpr uint32_t kFriendRosterActivate = 0x805D4834u;  // Pages::FriendList::OnActivate
constexpr uint32_t kFriendListUpdateStatuses = 0x805D2A50u;  // FriendList::UpdateStatuses (FriendList*)
constexpr uint32_t kMenuRkNetController = 0x809C20D8u;
constexpr uint32_t kMenuCanExchangeFriendData = 0x80656D9Cu;
constexpr uint32_t kBackButtonEnabled = 0x250;

uint32_t ReadGuestPointer(uint32_t address) {
    if (!Memory::Contains(address, 4)) {
        return 0;
    }
    const uint32_t value = Memory::Read32(address);
    return value && Memory::Contains(value, 4) ? value : 0;
}

uint32_t CurrentFriendList() {
    const uint32_t sectionMgr = ReadGuestPointer(kMenuSectionMgrPointer);
    const uint32_t section = sectionMgr ? ReadGuestPointer(sectionMgr) : 0;
    return section ? ReadGuestPointer(section + kMenuSectionFriendList) : 0;
}

int FriendCount(uint32_t friendList) {
    int count = 0;
    for (int i = 0; i < kMenuMaxFriends; ++i) {
        const uint32_t entry = friendList + i * kMenuFriendEntrySize;
        if ((Memory::Read32(entry) | Memory::Read32(entry + 4)) != 0) {
            ++count;
        }
    }
    return count;
}

// What WFCFriendsMenu's Back does on the root variant (page 142): no next
// page, and push the disconnect prompt.
void LeaveOnlineFromFriends(CpuContext* ctx, uint32_t page) {
    Memory::Write32(page + kMenuNextPage, static_cast<uint32_t>(-1));
    const uint32_t pushPage = Memory::Read32(Memory::Read32(page) + kPushPageVirtual);
    ctx->gpr[3] = page;
    ctx->gpr[4] = kPageDisconnectPrompt;
    ctx->gpr[5] = 0;
    InvokeIndirectCpu(pushPage, ctx);
}

bool IsFriendsScreen(uint32_t page) {
    return Enabled() && page && Memory::Read32(page + kPageId) == kPageFriends;
}

}  // namespace

}  // namespace NetworkHle::DirectOnline

using namespace NetworkHle::DirectOnline;

// Pages::WFCFriendsMenu::OnInit (r3 = page). Hides "Register Friend Code":
// everyone on the host is added as a friend automatically. Hidden the way
// FriendButton::SetMii (0x805D3B0C) hides an empty roster tile: no players
// may select it (PushButton::SetPlayerBitfield), and the control's hidden
// flag is set. "Friend Roster" stays the default selection.
extern "C" void DirectFriendsMenuInit_8064ca98(CpuContext* ctx) {
    constexpr uint32_t kRegisterButton = 0x48C;
    constexpr uint32_t kSetPlayerBitfield = 0x805BDBD4u;  // (PushButton*, u32 mask)
    constexpr uint32_t kControlHidden = 0x80;
    const uint32_t page = ctx->gpr[3];
    func_8064CA98(ctx);
    if (!IsFriendsScreen(page)) {
        return;
    }
    const uint32_t button = page + kRegisterButton;
    ctx->gpr[3] = button;
    ctx->gpr[4] = 0;
    InvokeIndirectCpu(kSetPlayerBitfield, ctx);
    Memory::Write8(button + kControlHidden, 1);
}
REGISTER_NATIVE_FUNCTION_AS(0x8064CA98, DirectFriendsMenuInit_8064ca98, "DirectFriendsMenuInit_8064ca98");

// Pages::Globe::AfterControlUpdate (r3 = globe page, 149), every frame. The
// globe's nameplate (NameWindow layout, LayoutUIControl at +0x1C8) shows the
// Mii name and, below it, a friend code: the player's own on the Friends
// menu, the selected friend's on the roster. Friend codes mean nothing on a
// direct host, so the code's two text panes are hidden after the game has
// updated them.
extern "C" void DirectGlobeUpdate_805e46c8(CpuContext* ctx) {
    constexpr uint32_t kNameplate = 0x1C8;
    constexpr uint32_t kSetPaneVisibility = 0x8063E54Cu;  // (LayoutUIControl*, char* pane, bool)
    // The pane names, in the game's static data.
    static constexpr std::array<std::pair<uint32_t, std::string_view>, 2> kCodePanes = {{
        {0x808953D4u, "user_id"},
        {0x808953DCu, "user_id_shadow"},
    }};
    const uint32_t globe = ctx->gpr[3];
    func_805E46C8(ctx);
    if (!Enabled() || !globe) {
        return;
    }
    static const bool namesMatch = [] {
        for (const auto& [address, name] : kCodePanes) {
            if (!Memory::Contains(address, static_cast<uint32_t>(name.size()) + 1)) return false;
            for (size_t i = 0; i <= name.size(); ++i) {
                const char expected = i < name.size() ? name[i] : '\0';
                if (static_cast<char>(Memory::Read8(address + static_cast<uint32_t>(i))) != expected) return false;
            }
        }
        return true;
    }();
    if (!namesMatch) {
        static bool warned = false;
        if (!warned) {
            warned = true;
            Log("menus: the globe's friend-code pane names aren't where expected; leaving friend codes shown");
        }
        return;
    }
    for (const auto& [address, name] : kCodePanes) {
        ctx->gpr[3] = globe + kNameplate;
        ctx->gpr[4] = address;
        ctx->gpr[5] = 0;
        InvokeIndirectCpu(kSetPaneVisibility, ctx);
    }
}
REGISTER_NATIVE_FUNCTION_AS(0x805E46C8, DirectGlobeUpdate_805e46c8, "DirectGlobeUpdate_805e46c8");

// Pages::WFCConnect::GetNextPage (r3 = page) -> page id.
extern "C" void DirectWfcConnectNextPage_806478c4(CpuContext* ctx) {
    func_806478C4(ctx);
    if (Enabled() && ctx->gpr[3] == kPageWfcMainMenu) {
        ctx->gpr[3] = kPageFriends;
    }
}
REGISTER_NATIVE_FUNCTION_AS(0x806478C4, DirectWfcConnectNextPage_806478c4, "DirectWfcConnectNextPage_806478c4");

// WFCFriendsMenu::OnBackButtonClick (r3 = page, r4 = button).
extern "C" void DirectFriendsBackButton_8064d4f4(CpuContext* ctx) {
    const uint32_t page = ctx->gpr[3];
    const uint32_t button = ctx->gpr[4];
    if (!IsFriendsScreen(page)) {
        func_8064D4F4(ctx);
        return;
    }
    LeaveOnlineFromFriends(ctx, page);
    // As on page 142: while friend data can't be exchanged, the button stays
    // disabled.
    if (const uint32_t controller = ReadGuestPointer(kMenuRkNetController)) {
        ctx->gpr[3] = controller;
        InvokeIndirectCpu(kMenuCanExchangeFriendData, ctx);
        if (ctx->gpr[3] == 0 && button) {
            Memory::Write32(button + kBackButtonEnabled, 0);
        }
    }
}
REGISTER_NATIVE_FUNCTION_AS(0x8064D4F4, DirectFriendsBackButton_8064d4f4, "DirectFriendsBackButton_8064d4f4");

// WFCFriendsMenu::OnBackPress (r3 = page): the B button.
extern "C" void DirectFriendsBackPress_8064d60c(CpuContext* ctx) {
    const uint32_t page = ctx->gpr[3];
    if (!IsFriendsScreen(page)) {
        func_8064D60C(ctx);
        return;
    }
    LeaveOnlineFromFriends(ctx, page);
}
REGISTER_NATIVE_FUNCTION_AS(0x8064D60C, DirectFriendsBackPress_8064d60c, "DirectFriendsBackPress_8064d60c");

// Pages::FriendList::AfterControlUpdate (r3 = page), every frame on the
// Friend Roster. Its tiles are assigned only in OnActivate, so when the
// friend count changes while it is open, activate it again.
extern "C" void DirectFriendRosterUpdate_805d4c10(CpuContext* ctx) {
    const uint32_t page = ctx->gpr[3];
    func_805D4C10(ctx);
    if (!Enabled() || !page || Memory::Read32(page + kPageState) != kPageStateActive) {
        return;
    }
    const uint32_t friendList = CurrentFriendList();
    if (!friendList) {
        return;
    }
    // Entry statuses (online, in a room...) are only worked out when the
    // roster activates or a friend's Mii arrives, so a friend whose status
    // arrives after that stays "not on Nintendo WFC". Work them out again
    // every second; the tiles read them every frame.
    static int framesUntilStatusUpdate = 0;
    if (--framesUntilStatusUpdate <= 0) {
        framesUntilStatusUpdate = 60;
        ctx->gpr[3] = friendList;
        InvokeIndirectCpu(kFriendListUpdateStatuses, ctx);
    }

    static uint32_t lastPage = 0;
    static int lastCount = -1;
    const int count = FriendCount(friendList);
    if (page != lastPage || lastCount < 0) {
        lastPage = page;
        lastCount = count;
        return;
    }
    if (count != lastCount) {
        lastCount = count;
        Log("friends: roster now has %d friend(s); refreshing it", count);
        ctx->gpr[3] = page;
        InvokeIndirectCpu(kFriendRosterActivate, ctx);
    }
}
REGISTER_NATIVE_FUNCTION_AS(0x805D4C10, DirectFriendRosterUpdate_805d4c10, "DirectFriendRosterUpdate_805d4c10");
