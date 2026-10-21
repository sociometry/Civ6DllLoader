--@ui-version=1
-- ===========================================================================
-- Civ6DllLoader_FrontEndUI.lua —— Loader 的主菜单设置面板
--
-- 与同目录 Civ6DllLoader_FrontEndUI.xml 配对。UiInject 在 MainMenuState::LoadUI
-- 之后调 LuaContext::Initialize("Civ6DllLoader/Civ6DllLoader_FrontEndUI")，
-- ForgeUI 按 base name 自动加载本文件。
--
-- 控件取用走 Controls.<ID>：本 context 的 xml 根节点是 ContextDefaults、
-- 控件直接挂在它下面，与 Base/Assets/UI/FrontEnd/MainMenu.xml 同构，
-- 因此与 MainMenu.lua:1770 的 Controls.VersionLabel 是同一套解析方式。
--
-- 状态持久化走 Loader 自己的 DllLoader 表（C++ 侧 ConfigIni）：
--   <exe目录>\Civ6DllLoader\config.ini    [Loader] ENABLE_GLOBAL / ENABLE_GAMECORE
-- 这是唯一的事实来源 —— 面板只是它的一个视图，读写都经 DllLoader 接口。
-- 不用 ModConfig（那是 Civ6BasePlugin 提供的，没装插件面板就失忆），
-- 也不用 Options.SetAppOption（对未在游戏 schema 里声明过的键是静默丢弃）。
--
-- 生效时机：改 ENABLE_GLOBAL 要重启游戏（Global 插件在启动时就加载完了）；
-- 改 ENABLE_GAMECORE 对下一次进对局有效（GameCore 那时才加载）。
-- ===========================================================================

local g_isPanelOpen = false;
local g_isQueued = false;   -- 本 context 当前是否在 popup 队列里

-- DllLoader 由 C++ Loader 直接注入，任何插件都不必在场。
local function HasLoaderApi()
    return type(DllLoader) == "table";
end

-- ===========================================================================
-- 文本（本地化）
--
-- xml 里所有 String 都写成 LOC_ 键，与游戏本体 / Mod 的写法一致。但这些键
-- 【不在游戏的 LocalizedText 表里】，必须由本文件提供实际文字，原因：
--   · Loader 不是 Mod，没有 .modinfo / UpdateDatabase，进不了本地化数据库；
--   · Localization_FinalRelease.dll 的导出只有读入口（Lookup / TryLookup /
--     HasKey / GetStringDictionary），没有任何 Add / Insert / Register；
--     LocCreate 只是给 Lookup 分配"查询结果的输出槽"（calloc 256 字节），
--     LocPushArgument 只往查询结果里已有的 {1} 槽填参，都不创建条目。
--
-- 所以文本表放在这里，随本 lua 一起走，语言按游戏当前 locale 自动选：
--   en_US      兜底
--   zh_Hans_CN 简体中文
--   zh_Hant_HK 繁体中文
-- Locale.GetCurrentLanguage() 返回 { Type = "zh_Hans_CN", DisplayName = ... }，
-- Type 就是 locale 串，也是 LocalizedText.Language 列的取值。
-- ===========================================================================
local kText = {
    LOC_CIV6DLLLOADER_TITLE = {
        en_US = "Civ6 Plugin Loader",
        zh_Hans_CN = "文明6插件加载器",
        zh_Hant_HK = "文明6插件載入器",
    },
    LOC_CIV6DLLLOADER_OPEN_TOOLTIP = {
        en_US = "Civ6 Plugin Loader Settings",
        zh_Hans_CN = "文明6插件加载器设置",
        zh_Hant_HK = "文明6插件載入器設定",
    },
    -- "Global DLL" 统一译作「全局插件」，"GameCore" 译作「游戏核心插件」。
    LOC_CIV6DLLLOADER_ENABLE_GLOBAL = {
        en_US = "Enable Global Plugin",
        zh_Hans_CN = "启用全局插件",
        zh_Hant_HK = "啟用全域插件",
    },
    LOC_CIV6DLLLOADER_ENABLE_GAMECORE = {
        en_US = "Enable GameCore Plugin",
        zh_Hans_CN = "启用游戏核心插件",
        zh_Hant_HK = "啟用遊戲核心插件",
    },
    -- 说明拆成一句一条 Label。不写进同一个 Label 的原因：
    -- Label 既有 WrapWidth 自动折行、又能识别 \n 手动换行，两者混用会让
    -- "下一句从哪开始"变得不可控（实测折行点会和 \n 打架）。
    LOC_CIV6DLLLOADER_HINT_GLOBAL = {
        en_US = "The global plugin loads once when the game starts, so a change takes effect after a restart.",
        zh_Hans_CN = "全局插件只在游戏启动时加载一次，修改后需重启游戏才生效。",
        zh_Hant_HK = "全域插件只在遊戲啟動時載入一次，修改後需重新啟動遊戲才生效。",
    },
    LOC_CIV6DLLLOADER_HINT_GAMECORE = {
        en_US = "The GameCore plugin loads with every match, so a change takes effect on your next game.",
        zh_Hans_CN = "游戏核心插件每局进入时加载，修改后对下一局生效。",
        zh_Hant_HK = "遊戲核心插件每局進入時載入，修改後對下一局生效。",
    },
    -- 警告：这两条是"关掉会有什么代价"，视觉上要和上面两条说明区分开
    -- （xml 里用暗红字，见 LoaderPanelWarn*）。
    LOC_CIV6DLLLOADER_WARN_DISABLE = {
        en_US = "Turning off plugin loading may break part of the functionality of mods that use this loader.",
        zh_Hans_CN = "关闭插件加载可能会让使用本加载器的 mod 部分功能丢失。",
        zh_Hant_HK = "關閉插件載入可能會讓使用本載入器的 mod 部分功能遺失。",
    },
    LOC_CIV6DLLLOADER_WARN_GAMECORE = {
        en_US = "With the GameCore plugin enabled, plugins that do not follow this loader's rules are not loaded, "
            .. "which may also break part of a mod's functionality.",
        zh_Hans_CN = "启用游戏核心插件时，不会加载不符合本加载器规则的插件，也可能导致部分 mod 功能丢失。",
        zh_Hant_HK = "啟用遊戲核心插件時，不會載入不符合本載入器規則的插件，也可能導致部分 mod 功能遺失。",
    },
}

-- 语言只判定一次：切换语言要重开游戏，运行期不会变。
local g_language = nil;

local function DetectLanguage()
    local lang = nil;
    if Locale ~= nil and Locale.GetCurrentLanguage ~= nil then
        lang = Locale.GetCurrentLanguage();
    end
    local code = nil;
    if type(lang) == "table" then
        code = lang.Type;
    end
    if type(code) ~= "string" then
        return "en_US";   -- 拿不到就按英文，绝不乱猜
    end
    if code:sub(1, 2):lower() == "zh" then
        -- 繁体：locale 里带 Hant（zh_Hant_HK / zh_Hant_TW）
        if code:find("Hant") ~= nil then
            return "zh_Hant_HK";
        end
        return "zh_Hans_CN";
    end
    return "en_US";
end

-- 取一条文本。表里没有就原样返回 tag —— 界面上直接看到 LOC_xxx 比空白好定位。
local function Text(tag)
    if g_language == nil then
        g_language = DetectLanguage();
    end
    local entry = kText[tag];
    if entry == nil then
        return tag;
    end
    return entry[g_language] or entry.en_US or tag;
end

local function ApplyLocalizedText()
    -- Label / Button / GridButton 都有 SetText；逐个显式列出而不是遍历 Controls，
    -- 写错 ID 时能立刻在日志里看出是哪个控件没生效。
    if Controls.LoaderPanelTitle ~= nil then
        Controls.LoaderPanelTitle:SetText(Text("LOC_CIV6DLLLOADER_TITLE"));
    end
    if Controls.LoaderEnableGlobal ~= nil then
        Controls.LoaderEnableGlobal:SetText(Text("LOC_CIV6DLLLOADER_ENABLE_GLOBAL"));
    end
    if Controls.LoaderEnableGameCore ~= nil then
        Controls.LoaderEnableGameCore:SetText(Text("LOC_CIV6DLLLOADER_ENABLE_GAMECORE"));
    end
    if Controls.LoaderPanelHintGlobal ~= nil then
        Controls.LoaderPanelHintGlobal:SetText(Text("LOC_CIV6DLLLOADER_HINT_GLOBAL"));
    end
    if Controls.LoaderPanelHintGameCore ~= nil then
        Controls.LoaderPanelHintGameCore:SetText(Text("LOC_CIV6DLLLOADER_HINT_GAMECORE"));
    end
    if Controls.LoaderPanelWarnDisable ~= nil then
        Controls.LoaderPanelWarnDisable:SetText(Text("LOC_CIV6DLLLOADER_WARN_DISABLE"));
    end
    if Controls.LoaderPanelWarnGameCore ~= nil then
        Controls.LoaderPanelWarnGameCore:SetText(Text("LOC_CIV6DLLLOADER_WARN_GAMECORE"));
    end
    if Controls.LoaderOpenButton ~= nil then
        -- tooltip 走 SetToolTipString（本体 1515 处、ActionPanel.lua:247 都是这个），
        -- 不是 SetText，也不是 SetToolTip。
        Controls.LoaderOpenButton:SetToolTipString(Text("LOC_CIV6DLLLOADER_OPEN_TOOLTIP"));
    end
end

local function ReadGlobalState()
    if HasLoaderApi() then
        return DllLoader.GetGlobalState();
    end
    return false;   -- 接口缺失：与 ini 的 fail-closed 保持一致
end

local function ReadGameCoreState()
    if HasLoaderApi() then
        return DllLoader.GetGameCoreState();
    end
    return false;
end

-- ---------------------------------------------------------------------------
-- 复选框：把控件与一个 Loader 开关绑起来。
-- 点击取值照抄 Options.lua:377 —— 先翻转 IsSelected()，再写回。
-- 写失败（ini 只读/被占用）时把控件状态回滚，别让界面显示与磁盘不一致。
-- ---------------------------------------------------------------------------
local function BindCheckBox(control, readFn, writeFn, label)
    if control == nil then
        return;
    end

    control:SetSelected(readFn());
    control:RegisterCallback(Mouse.eLClick, function()
        local enabled = not control:IsSelected();
        local ok = HasLoaderApi() and writeFn(enabled) or false;
        if ok then
            control:SetSelected(enabled);
        else
            print("Civ6DllLoader UI: failed to write " .. label .. " to config.ini");
        end
        UI.PlaySound("Play_UI_Click");
    end);
    control:RegisterCallback(Mouse.eMouseEnter, function()
        UI.PlaySound("Main_Menu_Mouse_Over");
    end);
end

-- 从 Loader 重新拉取两个开关的当前值。
-- 面板每次打开都要重刷：QueuePopup 会走一遍 context 的显示流程，
-- 控件可能被重置成默认态（实测两个勾都掉了）。
local function RefreshCheckBoxes()
    if Controls.LoaderEnableGlobal ~= nil then
        Controls.LoaderEnableGlobal:SetSelected(ReadGlobalState());
    end
    if Controls.LoaderEnableGameCore ~= nil then
        Controls.LoaderEnableGameCore:SetSelected(ReadGameCoreState());
    end
end

-- ---------------------------------------------------------------------------
-- 面板开关
-- ---------------------------------------------------------------------------
local function SetPanelOpen(open)
    if Controls.LoaderPanelRoot == nil or g_isPanelOpen == open then
        return;
    end
    g_isPanelOpen = open;

    -- 入队必须跟面板同生共死，不能在 OnInit 里常驻。
    -- 原因在 QueuePopup 本体（ForgeUI_UIManager::QueuePopup）：
    --   它把本 context 插到队首后，会对"入队前那个当前 popup"做两件事 ——
    --   清掉 m_uiFlags 的 0x8、再调它的虚函数 +336(1)，也就是【把它隐藏】。
    --   所以只要我们在 OnInit 就入队，排在它前面的主菜单会被一直按成隐藏，
    --   而我们自己的面板此时又是关着的，屏幕上就什么都不剩。
    -- 反过来，面板打开期间我们在队列里，ProcessPopupInput 才认我们，
    -- 悬停不会穿透到背后的主菜单（Layer="Modal" 只管绘制，管不了命中）。
    if open then
        if not g_isQueued then
            UIManager:QueuePopup(ContextPtr, PopupPriority.Current);
            g_isQueued = true;
        end
    elseif g_isQueued then
        UIManager:DequeuePopup(ContextPtr);
        g_isQueued = false;
    end

    -- 出入队都会动 context 的可见性（出队会把 context 置隐），统一显回来。
    -- context 必须一直可见，否则右上角那颗入口按钮跟着消失。
    -- 面板自身的显隐只由 LoaderPanelRoot 控制。
    ContextPtr:SetHide(false);

    Controls.LoaderPanelRoot:SetHide(not open);
    if open then
        RefreshCheckBoxes();
    end

    UI.PlaySound(open and "UI_Screen_Open" or "UI_Screen_Close");
end

local function AddClickAndHover(control, onClick)
    if control == nil then
        return;
    end
    control:RegisterCallback(Mouse.eLClick, onClick);
    control:RegisterCallback(Mouse.eMouseEnter, function()
        UI.PlaySound("Main_Menu_Mouse_Over");
    end);
end

-- ---------------------------------------------------------------------------
-- 生命周期
-- ---------------------------------------------------------------------------
-- isReload：[hotload] 传入，true 表示这次是热重载重建的 context。
-- 两条路径都走同一套代码：本函数不碰 popup 队列，队列完全交给
-- SetPanelOpen 与面板同步（热重载后的新 context 自然也不在队列里，
-- 所以这里只需把 g_isQueued 复位，不会有失效条目留下）。
function OnInit(isReload)
    -- 面板初始隐藏。xml 上的 Hidden="1" 不可靠（根节点是 Context，
    -- 子控件的 Hidden 在 Attach 阶段可能没生效），这里显式关一次。
    Controls.LoaderPanelRoot:SetHide(true);
    g_isPanelOpen = false;

    -- 【不再在 OnInit 入队】QueuePopup 会顺手把"入队前的当前 popup"隐藏，
    -- 常驻入队等于把主菜单一直按住。入队/出队改在 SetPanelOpen 里跟面板同步。
    g_isQueued = false;
    ContextPtr:SetHide(false);

    AddClickAndHover(Controls.LoaderOpenButton, function()
        SetPanelOpen(not g_isPanelOpen);
    end);

    AddClickAndHover(Controls.LoaderPanelClose, function()
        SetPanelOpen(false);
    end);

    -- 文本必须在 BindCheckBox 之前落地：BindCheckBox 会 SetSelected，
    -- 但不碰文字；顺序其实无所谓，这里放前面是为了让"界面先有字"更直观。
    ApplyLocalizedText();

    BindCheckBox(Controls.LoaderEnableGlobal, ReadGlobalState,
        function(v) return DllLoader.SetGlobalState(v); end, "ENABLE_GLOBAL");
    BindCheckBox(Controls.LoaderEnableGameCore, ReadGameCoreState,
        function(v) return DllLoader.SetGameCoreState(v); end, "ENABLE_GAMECORE");

    if not HasLoaderApi() then
        print("Civ6DllLoader UI: DllLoader API missing; toggles are read-only");
    end
    print("Civ6DllLoader UI: settings panel ready (locale="
        .. tostring(g_language) .. ")");
end

function OnShutdown()
    -- 只有还在队列里才出队，否则 context 销毁后队列里会留失效条目。
    -- 本 context 没有登记 Events.* / LuaEvents.*，无需 Remove。
    if g_isQueued then
        UIManager:DequeuePopup(ContextPtr);
        g_isQueued = false;
    end
    g_isPanelOpen = false;
end

-- ESC 关面板。只在面板开着时吃按键，否则返回 false 让主菜单照常处理。
function OnInputHandler(pInputStruct)
    if not g_isPanelOpen then
        return false;
    end
    if pInputStruct:GetMessageType() == KeyEvents.KeyUp
        and pInputStruct:GetKey() == Keys.VK_ESCAPE then
        SetPanelOpen(false);
        return true;
    end
    return false;
end

-- ---------------------------------------------------------------------------
ContextPtr:SetInitHandler(OnInit);
ContextPtr:SetShutdown(OnShutdown);
ContextPtr:SetInputHandler(OnInputHandler, true);
