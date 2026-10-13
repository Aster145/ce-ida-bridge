# CE ↔ IDA 自动校准

在 IDA 命中 ARM64 游戏代码断点后，自动导出附近字节，由 Cheat Engine 在模拟器进程中执行 AOB 搜索，计算宿主地址与游戏地址的差值。

适用流程：Windows 上使用 CE 7.x、IDA 的 ARM64 Remote GDB 调试会话，以及 Eden / Ryujinx。脚本没有绑定模拟器进程名或 GDB 端口；IDA 必须已能暂停游戏并读取运行时内存。

## 使用

1. 在 IDA 的 **Remote GDB debugger → Process options** 中配置模拟器地址与端口，例如 Eden 的 `127.0.0.1:6543`。
2. 在 IDA 中通过 **File → Script file** 加载 [`ida_ce_bridge.py`](ida_ce_bridge.py)。每次打开 IDA 加载一次。
3. CE 选择对应的 Eden / Ryujinx 进程，打开 [`CE_IDA自动校准.CT`](CE_IDA自动校准.CT)，允许执行 Lua 脚本。
4. 在 IDA 中设置一个 ARM64 代码执行断点，运行至命中后保持暂停。
5. CE 自动搜索并列出匹配地址和差值。若存在多个候选，在下拉框中选择对应的映射。
6. 填入 CE 搜到的金钱或血量地址，点击 **换算游戏地址**，复制结果到 IDA 调试内存窗口核对。

也可以直接在 CE 的 **Memory View → Tools → Lua Engine** 中打开并执行 [`ce_ida_bridge.lua`](ce_ida_bridge.lua)。

## 地址关系

```text
映射差值 Δ = CE 参考地址 − IDA/GDB 游戏参考地址
游戏目标地址 = CE 目标地址 − Δ
```

参考样本从断点后 `+4` 字节开始，避开当前 ARM64 软件断点的指令字节。优先读取 64 字节，读取不足时尝试 32、16 字节。样本来自调试目标运行时内存，不使用静态 IDB 字节。

AOB 可能同时命中镜像或副本。代码参考地址与 CE 目标地址必须使用同一个映射差值；单个代码样本不能证明堆地址换算必然正确。重启游戏或模拟器后重新校准。

## 控制与排查

- IDA 已暂停时，可在 Python 控制台执行 `ce_ida_export_now()` 重新发送样本。
- 样本早于 CE 工具启动时，点击 **搜索最近样本**。
- 执行 `ce_ida_stop()` 停止 IDA 自动导出；再次加载 Python 脚本可恢复。
- 无匹配时，核对 CE 进程、MEM_MAPPED 扫描设置，并换一个代码断点；取样区域避免放置其他断点。
- 扫描期间保持游戏暂停，不要切换 CE 进程。

两个脚本通过 `%TEMP%\CE_IDA_Bridge\anchor.txt` 交换样本，需要同一 Windows 用户环境。同一时间使用一个校准会话。CE 不另行连接 GDB，不占用 IDA 的调试端口；脚本不写入游戏内存，也不自动继续游戏。

完整步骤见 [使用说明](使用说明.txt)。

## 验证状态

已按 IDA 7.7 的 Python 接口检查，并通过 Python / Lua 语法和模拟接口联动检查，涵盖自动接收、多个/单个/零匹配、换算、扫描失败及进程切换。尚未在实际 Eden / Ryujinx 游戏会话中验证 AOB 命中。
