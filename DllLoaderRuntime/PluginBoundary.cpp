#include "pch.h"
#include "PluginBoundary.h"

#include "Runtime.h"
#include "../common/Logger.h"

#include <Windows.h>
#include <atomic>
#include <cstring>
#include <string.h>   // strnlen / memcpy 的全局声明（MSVC）
#include <intrin.h>   // __debugbreak

namespace PluginBoundary {
namespace {

// 本线程持有的 Loader 锁层数。thread_local：只看自己这一条线程。
// 若某次异常把中间帧的 LoaderLockScope 析构跳过了，这个值会停在非 0 —— 正是
// 我们想让它“响”的信号。
thread_local int g_lockDepth = 0;

// 违反不变量的上报：每个调用点（以字符串字面量地址标识）最多报一次，避免刷屏。
constexpr int kMaxReportedSites = 64;
const char* g_reportedSites[kMaxReportedSites] = {};
std::atomic<int> g_reportedCount{ 0 };

bool FirstTimeForSite(const char* what) {
    const int n = g_reportedCount.load(std::memory_order_acquire);
    const int scan = n < kMaxReportedSites ? n : kMaxReportedSites;
    for (int i = 0; i < scan; ++i) {
        if (g_reportedSites[i] == what) return false;
    }
    const int slot = g_reportedCount.fetch_add(1, std::memory_order_acq_rel);
    if (slot < kMaxReportedSites) {
        g_reportedSites[slot] = what;
        return true;
    }
    return false;
}

void ReportLockedAccess(const char* what) {
    if (FirstTimeForSite(what)) {
        Logger::Log("[BUG] 持锁状态下访问插件内存（违反 PluginBoundary 不变量）: %s "
                    "(LockDepth=%d) —— 该访存必须在取锁之前完成",
                    what ? what : "?", g_lockDepth);
    }
#if defined(_DEBUG) || defined(CIV6_LOADER_STRICT)
    __debugbreak();
#endif
}

}  // namespace

// ---------------------------------------------------------------- 叶子探针
// 只允许 POD 局部变量：这些函数里不能出现任何需要展开的 C++ 对象（MSVC C2712）。

__declspec(noinline) bool TryReadRaw(const void* src, void* dst, size_t len, size_t maxLen) {
    if (!src || !dst || len == 0 || len > maxLen) return false;
    __try {
        memcpy(dst, src, len);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

__declspec(noinline) bool TryStrLenRaw(const char* s, size_t limit, size_t& outLen) {
    outLen = 0;
    if (!s || limit == 0) return false;
    __try {
        const size_t n = strnlen(s, limit);
        if (n >= limit) return false;   // 限长内找不到结尾符 -> 当成坏数据
        outLen = n;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// ---------------------------------------------------------------- 组合

bool CopyCString(const char* src, std::string& out) {
    out.clear();
    if (!src) return false;
    if (g_lockDepth != 0) ReportLockedAccess("CopyCString");

    size_t len = 0;
    if (!TryStrLenRaw(src, kMaxPluginString, len)) return false;
    if (len == 0) return true;                        // 空串合法
    out.resize(len);
    if (!TryReadRaw(src, out.data(), len, kMaxPluginString)) {
        out.clear();
        return false;
    }
    return true;
}

bool CopyRawBytes(const void* src, void* dst, size_t len, size_t maxLen) {
    if (!src || !dst || len == 0) return false;
    if (len > maxLen) return false;
    if (g_lockDepth != 0) ReportLockedAccess("CopyRawBytes");
    return TryReadRaw(src, dst, len, maxLen);
}

// ---------------------------------------------------------------- 页属性探测
// 复用 Runtime 的实现：逐区域 VirtualQuery，要求 MEM_COMMIT 且不含
// PAGE_NOACCESS / PAGE_GUARD；写探测另外要求写权限位。

bool IsReadable(const void* p, size_t len) {
    return Runtime::IsReadableSpan(p, len);
}

bool IsWritable(const void* p, size_t len) {
    return Runtime::IsWritableSpan(p, len);
}

bool IsReadableWritable(const void* p, size_t len) {
    return IsReadable(p, len) && IsWritable(p, len);
}

// ---------------------------------------------------------------- 锁深度

LoaderLockScope::LoaderLockScope() {
    ++g_lockDepth;
}

LoaderLockScope::~LoaderLockScope() {
    --g_lockDepth;
}

}  // namespace PluginBoundary
