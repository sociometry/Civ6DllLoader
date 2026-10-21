#pragma once
// Profiler — Loader 自身的耗时分析器。
//
// 开关：config.ini 的 [Loader] ENABLE_PROFILER（默认 false，只能手改，没有 Writer、
// 没有 UI、没有 Lua 接口）。**不经过 ENABLE_DEBUG_LOG** —— 两者是独立开关：
// DEBUG_LOG 管"要不要打细颗粒度的诊断"，PROFILER 管"要不要量耗时"。
// 性能分析器本身也受本开关控制：关着时 Begin/End 都是空操作，不取时间、不分配、
// 不打日志，热路径上只剩一次 bool 判断。
//
// 输出：与 Loader 其它日志同一个文件（Civ6DllLoader_Loader.log），不用另开文件 ——
// 时序信息只有和别的日志放在一条时间线上才对得上。行格式：
//   [Prof] <scope> <elapsed_ms> ms [<附注>]
// 结束时打一条汇总，按 scope 聚合 count / total / max，按 total 降序：
//   [Prof] === summary (N scopes, M samples) ===
//   [Prof]   total=1234.567ms count=42 max=88.000ms  <scope>
//
// 用法：
//   {
//       PROFILE_SCOPE("UiInject::Install");
//       ...
//   }
// 作用域结束自动 End（RAII），异常路径也能收尾。也提供手动一对：
//   Profiler::Begin("x") / Profiler::End("x")  —— 只在嵌套不成对时用，优先 RAII。
//
// 计时用 QueryPerformanceCounter（单调、不受系统时间调整影响）。Begin 里取频率并缓存。
// 递归同名 scope 不特殊处理：栈式配对，count 会各自计一次（这是想要的，
// 比如插件加载里嵌套调用 LoadPluginsOf 时两条都该量到）。

#include <cstdint>

namespace Profiler {

// 开关状态由调用方注入：Profiler 在 common/，不认识 config.ini
// （那是 DllLoaderRuntime 的模块，不能反过来被 common 依赖）。
// Loader 在启动序列最开始调一次 SetEnabled(CfgIni::ReadProfilerEnabled())；
// 之前默认 false，所以 Begin/End 在此之前都是空操作。
void SetEnabled(bool enabled);

// 开关是否打开。热路径上只读一个原子 bool。
bool Enabled();

// 开始计时。返回起始 tick；未启用时返回 0 且调用方不必配对 End（End 会自己忽略）。
int64_t Begin(const char* scope);

// 结束计时并写一行日志。beginTick == 0（未启用）或 scope 为空时直接返回。
// note 可为 nullptr（额外的附注，比如插件名、候选数）。
void End(const char* scope, int64_t beginTick, const char* note = nullptr);

// 打汇总（按 scope 聚合）。由 Loader 在阶段 A 结束时调一次；
// 阶段 B（InitializeGameCorePhase）结束时再调一次，看它是累加还是每次清空见实现。
void LogSummary(const char* tag);

// 清空累计（主要由测试/多次汇总用）。
void Reset();

// 毫秒数换算：tick 差值 -> double ms。
double TicksToMs(int64_t ticks);

}  // namespace Profiler

// RAII 作用域计时器。未启用时构造/析构都只做一次 bool 判断。
class ProfilerScope {
public:
    explicit ProfilerScope(const char* scope, const char* note = nullptr)
        : scope_(scope), note_(note), start_(Profiler::Begin(scope)) {}

    ~ProfilerScope() { Profiler::End(scope_, start_, note_); }

    ProfilerScope(const ProfilerScope&) = delete;
    ProfilerScope& operator=(const ProfilerScope&) = delete;

    // 补一个附注（构造时还不知道的信息，比如加载了几个候选）。
    void SetNote(const char* note) { note_ = note; }

private:
    const char* scope_;
    const char* note_;
    int64_t start_;
};

#define PROFILER_CONCAT_IMPL(a, b) a##b
#define PROFILER_CONCAT(a, b) PROFILER_CONCAT_IMPL(a, b)
#define PROFILE_SCOPE(name) \
    ProfilerScope PROFILER_CONCAT(profile_scope_, __LINE__)(name)
#define PROFILE_SCOPE_NOTE(name, note) \
    ProfilerScope PROFILER_CONCAT(profile_scope_, __LINE__)(name, note)
