#pragma once
// Civ6DllLoader - 插件内存安全边界。
//
// ============================ 不变量（Invariant） ============================
// 任何持有 Loader 内部锁的代码，只允许访问 Loader 自有内存：
//     g_pluginLifecycleMutex / g_pushStateMutex / g_scriptStateMutex /
//     g_captureMutex / PatchRegistry 的 CRITICAL_SECTION
// 插件提供的指针，必须在本线程【未持锁】时先经本文件的 Copy*/TryRead* 抄进
// Loader 自有存储，再进锁使用。
//
// 为什么：MSVC 默认 /EHsc 下，硬件异常（访问违例）穿过 C++ 帧时不会执行析构，
// lock_guard 不释放 -> 该锁被永久持有 -> 其它线程永久阻塞（游戏卡死，无报错）。
// 把“可能出错的访存”放到取锁之前，出错路径上就没有任何锁被持有。
//
// 其它两类同族入口（不读内存，但要探页属性）：
//   1) 宿主往插件给的【输出参数】写：InstallHook(original)、GetImageInfo(outInfo)、
//      RegisterGlobalCapture(out 槽) -> 用 IsWritable 先探；
//   2) 宿主读插件给的【函数地址】再去调：用 IsReadable 先探。
// 页属性探测基于 VirtualQuery，对任意地址都安全，不需要 SEH。
// ===========================================================================

#include <cstddef>
#include <cstdint>
#include <string>

namespace PluginBoundary {

// ---- 上限 ----
// 插件提供的字符串上限（超长 / 无结尾符 -> 视为坏数据）。名字类字段本应很短。
constexpr size_t kMaxPluginString = 4096;
// 二进制 / 补丁字节上限。与字符串上限分开，避免较大的补丁被误拒。
constexpr size_t kMaxPluginRawBytes = 1u << 20;   // 1 MiB
// 单次 PushLuaMethods 的方法条数上限。
constexpr uint32_t kMaxLuaMethodsPerCall = 512;
// MinHook 需要读取的目标函数前导字节数（校验 target 可读用）。
constexpr size_t kMinHookTargetSpan = 32;

// ---- 叶子探针 ----
// __try 在本工程多处出现（本文件的叶子探针、Civ6MessageBus::CallHandlerSeh、
// Civ6DLLHookLoaderAPI.cpp 的若干 leaf、LoaderHooks.cpp 的 GetRuleSetName、UiInject 的
// Call*Safe）。统一约定：写 __try 的函数只允许 POD 局部变量（MSVC C2712 不允许
// “需要对象展开的函数”里写 __try），异常在叶子内部就被吃掉——调用方的 C++ 对象
// 从头到尾不知道发生过异常，因此不存在“析构被跳过”的问题。
__declspec(noinline) bool TryReadRaw(const void* src, void* dst, size_t len, size_t maxLen);
__declspec(noinline) bool TryStrLenRaw(const char* s, size_t limit, size_t& outLen);

// ---- 组合（调用方必须在未持锁状态下调用）----
// 插件字符串 -> Loader 自有 std::string。两步：先量长度（strnlen 不会多读一个
// 字节），再按需精确拷贝。若直接读固定长度，紧贴页尾的合法短串会被误判为坏地址。
bool CopyCString(const char* src, std::string& out);

// 插件二进制 -> Loader 自有缓冲。
bool CopyRawBytes(const void* src, void* dst, size_t len,
                  size_t maxLen = kMaxPluginRawBytes);

// POD 结构体整体抄写（结构体本身也是插件内存）。之后读副本字段不再碰插件内存。
template <class T>
bool CopyPod(const T* src, T& out) {
    return TryReadRaw(src, &out, sizeof(T), sizeof(T));
}

// ---- 页属性探测（VirtualQuery，任何地址都安全）----
bool IsReadable(const void* p, size_t len);
bool IsWritable(const void* p, size_t len);
bool IsReadableWritable(const void* p, size_t len);

// ---- 本线程 Loader 锁深度（断言 + 看门狗）----
// 用法：与既有 lock_guard 并列，紧跟在取锁那一行之后，作用域相同：
//     lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
//     LoaderLockScope lockScope;
// 不变量被违反时（持锁仍调用 Copy*/TryRead*）会低频告警，Debug 下断点。
int LockDepth();

struct LoaderLockScope {
    LoaderLockScope();
    ~LoaderLockScope();
    LoaderLockScope(const LoaderLockScope&) = delete;
    LoaderLockScope& operator=(const LoaderLockScope&) = delete;
};

}  // namespace PluginBoundary
