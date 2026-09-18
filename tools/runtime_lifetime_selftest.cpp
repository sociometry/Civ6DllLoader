// Build/run with tools/run_runtime_lifetime_selftest.ps1 (initializes x64 MSVC automatically).
// Links the production message bus and in-flight implementation; no game DLL required.
#include "../DllLoaderRuntime/Civ6MessageBus.h"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <thread>

namespace Logger { void Log(const char*, ...) {} }
using namespace std::chrono_literals;

static void Check(bool ok, const char* message) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        std::abort();
    }
}

static void CheckGenerations() {
    auto* old = PluginInFlight::BeginLifetime(L"generation");
    PluginInFlight::SetAllowed(old, true);
    Check(bool(PluginInFlight::Enter(old, PluginInFlight::Kind::Message)), "old generation initially active");
    PluginInFlight::SetAllowed(old, false);
    PluginInFlight::WaitAll(old, L"generation");
    auto* next = PluginInFlight::BeginLifetime(L"generation");
    PluginInFlight::SetAllowed(next, true);
    Check(old != next && PluginInFlight::Resolve(L"generation") == next, "fresh generation published");
    Check(!PluginInFlight::Enter(old, PluginInFlight::Kind::Message), "old snapshot stays disabled");
    Check(bool(PluginInFlight::Enter(next, PluginInFlight::Kind::Message)), "new generation active");
}

static void CheckMovedGuardDrain() {
    auto* owner = PluginInFlight::BeginLifetime(L"moved-guard");
    PluginInFlight::SetAllowed(owner, true);
    std::promise<void> entered, release;
    auto released = release.get_future().share();
    auto callback = std::async(std::launch::async, [&] {
        PluginInFlight::Guard guard;
        {
            guard = PluginInFlight::Enter(owner, PluginInFlight::Kind::PushMethods);
            Check(bool(guard), "move-assigned guard acquired");
        }
        entered.set_value();
        released.wait();
    });
    Check(entered.get_future().wait_for(2s) == std::future_status::ready, "guard scope entered");
    PluginInFlight::SetAllowed(owner, false);
    auto drain = std::async(std::launch::async, [&] { PluginInFlight::WaitAll(owner, L"moved-guard"); });
    Check(drain.wait_for(50ms) == std::future_status::timeout, "moved guard remains active outside inner scope");
    release.set_value();
    Check(drain.wait_for(2s) == std::future_status::ready, "moved guard releases count");
    callback.get();
    drain.get();
}

// Broadcast snapshots both handlers before calling either. Whichever runs first removes
// the other and reloads its owner. The captured old handler must never run in that broadcast.
static void CheckStaleBroadcast(bool reloadOwner) {
    Civ6MessageBus bus;
    const char* names[] = { "first", "second" };
    const wchar_t* owners[] = { L"broadcast-first", L"broadcast-second" };
    int oldCalls = 0;
    int newCalls = 0;
    int replaced = -1;
    for (int i = 0; i < 2; ++i) {
        auto* lifetime = PluginInFlight::BeginLifetime(owners[i]);
        PluginInFlight::SetAllowed(lifetime, true);
        Check(bus.RegisterHandler(names[i], [&, i](const char*, const void*, size_t) {
            if (++oldCalls != 1) return;
            replaced = 1 - i;
            if (reloadOwner) {
                auto* old = PluginInFlight::Resolve(owners[replaced]);
                PluginInFlight::SetAllowed(old, false);
                bus.UnregisterOwner(owners[replaced]);
                PluginInFlight::WaitAll(old, owners[replaced]);
                PluginInFlight::SetAllowed(PluginInFlight::BeginLifetime(owners[replaced]), true);
            }
            Check(bus.RegisterHandler(names[replaced], [&](const char*, const void*, size_t) {
                ++newCalls;
            }, owners[replaced]), "register replacement");
        }, owners[i]), "register initial handler");
    }
    bus.Broadcast("snapshot", nullptr, 0);
    Check(oldCalls == 1 && newCalls == 0, "removed/replaced broadcast snapshot skipped");
    bus.SendTo(names[replaced], "next", nullptr, 0);
    Check(newCalls == 1, "replacement receives future messages");
}

static void CheckDrainAndSelfRemoval() {
    Civ6MessageBus bus;
    std::promise<void> entered, release;
    auto released = release.get_future().share();
    bus.RegisterHandler("blocking", [&](const char*, const void*, size_t) {
        entered.set_value();
        released.wait();
    }, L"drain-owner");
    auto dispatch = std::async(std::launch::async, [&] { bus.SendTo("blocking", "", nullptr, 0); });
    Check(entered.get_future().wait_for(2s) == std::future_status::ready, "callback entered");
    auto remove = std::async(std::launch::async, [&] { bus.UnregisterOwner(L"drain-owner"); });
    Check(remove.wait_for(50ms) == std::future_status::timeout, "unregister drains executing callback");
    release.set_value();
    Check(remove.wait_for(2s) == std::future_status::ready, "unregister finishes after callback");
    dispatch.get();
    remove.get();

    int calls = 0;
    bus.RegisterHandler("self", [&](const char*, const void*, size_t) {
        ++calls;
        bus.UnregisterOwner(L"self-owner");
    }, L"self-owner");
    bus.SendTo("self", "", nullptr, 0);
    bus.SendTo("self", "", nullptr, 0);
    Check(calls == 1, "callback can unregister itself without deadlock");
}

static void CheckReplacementDrainsOnlyOldEntry() {
    Civ6MessageBus bus;
    std::promise<void> oldEntered, releaseOld, published, newEntered, releaseNew;
    auto oldRelease = releaseOld.get_future().share();
    auto newRelease = releaseNew.get_future().share();
    bus.RegisterHandler("replace", [&](const char*, const void*, size_t) {
        oldEntered.set_value();
        oldRelease.wait();
    }, L"replacement-owner");
    auto oldDispatch = std::async(std::launch::async, [&] { bus.SendTo("replace", "", nullptr, 0); });
    Check(oldEntered.get_future().wait_for(2s) == std::future_status::ready, "old callback entered");
    auto replace = std::async(std::launch::async, [&] {
        return bus.RegisterHandler("replace", [&](const char*, const void*, size_t) {
            newEntered.set_value();
            newRelease.wait();
        }, L"replacement-owner", [&] { published.set_value(); return true; });
    });
    Check(published.get_future().wait_for(2s) == std::future_status::ready, "replacement validated");
    auto newDispatch = std::async(std::launch::async, [&] { bus.SendTo("replace", "", nullptr, 0); });
    Check(newEntered.get_future().wait_for(2s) == std::future_status::ready, "new callback entered");
    Check(replace.wait_for(50ms) == std::future_status::timeout, "replacement drains old callback");
    releaseOld.set_value();
    Check(replace.wait_for(2s) == std::future_status::ready, "replacement does not wait for new callback");
    Check(replace.get(), "replacement succeeded");
    releaseNew.set_value();
    oldDispatch.get();
    newDispatch.get();
}

int main() {
    CheckGenerations();
    CheckMovedGuardDrain();
    CheckStaleBroadcast(false);
    CheckStaleBroadcast(true);
    CheckDrainAndSelfRemoval();
    CheckReplacementDrainsOnlyOldEntry();
    std::puts("PASS: runtime lifetime regression tests");
}
