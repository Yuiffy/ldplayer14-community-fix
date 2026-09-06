# NVIDIA 线程退出清理实验

此目录是研究原型，不包含在 `v0.1.0-alpha.1` 信号量修补包中。短时对照已经通过，尚未完成《碧蓝航线》长期运行验证，不能称为稳定修复或黑屏修复。

## 已验证的机制

在当前 LD14 环境，NVIDIA 的 mimalloc TLS 回调先清理线程堆；随后同一个驱动的 `DllMain(DLL_THREAD_DETACH)` 又分配新堆。新堆没有后续清理，已释放对象占用的页面继续挂在退出线程名下。

12 轮 Android EGL 离屏测试的 A/B/A 对照：

| 模式 | 新残留线程堆 | 残留页数 | 其中完全空闲的页面 |
| --- | ---: | ---: | ---: |
| 原始清理 | 13 | 245 | 14.56 MiB |
| 补充最后一次清理 | 0 | 0 | 0 |
| 撤掉实验后 | 13 | 245 | 14.69 MiB |

每组像素检查均为 12/12 通过，页结构与释放链无验证错误。统计对象是本轮创建的堆，不能把这些数字理解为整个进程已经没有缓存或其他泄漏。

原型在 NVIDIA DLL 入口完成 `DLL_THREAD_DETACH` 后检查当前默认堆，只有堆的线程身份和 backing heap 都匹配时，才再次调用该驱动自己的 mimalloc 清理函数。没有扫描并释放历史地址，也不清空工作集。原有信号量修补可以同时使用。

## 运行条件

- Windows x64、64 位 Python 3.10 或更新版本。
- LD14 14.0.26.1，以及主项目校验通过的 renderer / fastpipe2 文件。
- NVIDIA 616.64，`nvoglv64.dll` SHA256 必须为 `970bb2528b3c12867997ac1b344eb6b9b356e18bc8a1ad768238e3306b58a4c9`。
- Frida `17.17.0`。其他驱动或文件不匹配时，程序会拒绝应用。

不要修改 SHA256 或 RVA 来绕过兼容性检查。其他驱动版本需要重新分析。

## 安装与测试

在完整仓库根目录打开 PowerShell，按主项目说明配置实例并启动雷电，然后执行：

```powershell
py -3 -m pip install frida==17.17.0
py -3 experimental/nvidia-thread-cleanup.py
py -3 experimental/nvidia-thread-cleanup.py --apply --minutes 240
```

第二条命令只检查兼容性，不应用补丁。第三条命令在当前选定进程中启用实验清理，终端保持运行。若没有保存主项目配置，可以显式增加 `--console '你的LD14安装目录' --index 实例编号`。若目标进程为管理员权限，测试终端也需要相同权限。

输出出现 `EXPERIMENT ACTIVE` 才表示本次启用成功；`cleaned_heaps` 会随着相关线程退出增加。日志保存在仓库 `logs` 目录，包含时间、私有提交、工作集、句柄数和清理计数。

先比较相同游戏阶段的 30-60 分钟，再进行 2-4 小时挂机。记录图形异常、闪退及驱动恢复时间。不要只看某次 Private Bytes 下降；需观察长期增长速度是否改变。

## 长期运行两个修复

4 小时是实验命令的默认时限，不是修复机制的限制。`--minutes 0` 表示持续到进程退出或主动停止；同时增加 `--with-semaphore` 可应用旧信号量修补：

```powershell
py -3 experimental/nvidia-thread-cleanup.py --apply --with-semaphore --minutes 0
```

需要跨雷电重启持续启用时，使用新的后台守护。在完整仓库根目录运行：

```powershell
powershell.exe -NoProfile -File .\Manage-LD14-Guard.ps1 -Action Install
```

管理脚本使用 PATH 中的 `python.exe`，或通过 `-Python 'C:\你的Python目录\python.exe'` 指定 64 位解释器。Frida 安装在单独目录时可增加 `-DependencyDir 'C:\你的依赖目录'`。这些本机路径保存在被 Git 忽略的 `.ld14-guard-local.json`，不要上传。

- `Install` 通过 Windows 任务计划程序启动后台守护，并为当前用户添加登录触发。任务以当前交互用户的普通权限运行，无执行时限，不依赖启动它的终端。首次使用仍需按主项目配置 LD14 目录和实例。
- 守护不启动雷电；你按平时方式打开选定实例后，它会自动检查版本、应用信号量修补并保持 NVIDIA 清理有效。
- 同一实例只能运行一个守护。实例正常退出后守护会等待；再次启动后重新校验并应用两个修复。
- 双击 `Check-LD14-Guard.cmd` 检查状态。`running: true`、`state: active`、`semaphore_patch: patched` 和 `nvidia_cleanup: true` 才表示两项均在运行。`waiting_for_ld14` 表示等待雷电启动。
- 双击 `Stop-LD14-Guard.cmd` 正常停止守护并撤掉 NVIDIA 钩子，同时暂停计划任务及登录触发；信号量修补仍保留到雷电退出。`Start-LD14-Guard.cmd` 会重新启用任务及已安装的登录触发。
- 移除登录启动并停止守护：`powershell.exe -NoProfile -File .\Manage-LD14-Guard.ps1 -Action Uninstall`。再重启雷电可完全回退本次进程内修补。

守护无自动到期时间，不依赖 PowerShell 窗口保持打开。驱动或雷电文件不匹配、清理状态异常时，它会拒绝继续修补该进程，并在 `logs/guard/status.json` 和 `events.jsonl` 中保留错误。异常不会通过自动重启游戏来掩盖。

旧版使用登录启动快捷方式，但实测曾出现守护无退出记录地消失，之后内存重新增长。退出原因尚未确定。新版执行一次 `Install` 或 `Start` 即可迁移到独立计划任务；确认守护启动后移除本项目旧快捷方式。任务记录退出结果，每次启动仍校验版本、原始指令和单实例锁。进程异常退出后需要通过 `Start-LD14-Guard.cmd` 重新启用；Windows 自动失败重试没有通过本机实测，本版不依赖该机制。

`Check-LD14-Guard.cmd` 会同时显示计划任务状态。守护不存在时返回 `state: not_running`；心跳超过 90 秒未更新时返回 `state: unresponsive`，此时不能确认清理仍然有效。旧样本移到 `last_recorded`，不再作为当前内存或补丁状态显示。`logs/guard/controller.log` 记录控制器启动、正常退出、Python 异常和可捕获的原生故障；被强行终止时仍可能没有退出日志，可结合 `scheduled_task.last_result` 排查。

`logs/guard/current-experiment.json` 保留当前会话最近 120 个样本及累计采样数；完整样本写入轮转的 `current-experiment.jsonl`，最多 4 个各约 4 MiB 的文件。状态事件也会轮转。新的守护会话沿用这一日志上限；原有有限时长实验的完整 JSON 不受影响。

长期运行方式不等于已证实的稳定修复。已积累的泄漏不会被追溯清空；需要干净测试基线时应重启雷电。当前版本仍只支持上述已验证环境。

## 停止与回退

按 Ctrl+C、到达时限或目标退出时结束实验。正常脱离会恢复驱动入口字节，并在日志写入 `driver_code_restored: true`。此后新增线程不再接受实验清理；已清理的资源不会恢复成泄漏状态。

退出 LD14 会让本次进程内改动全部失效。程序不覆盖磁盘上的厂商 DLL、不安装服务、不修改驱动配置；单次实验下次启动后需要重新启用，后台守护则会自动重新校验和应用。关闭单次实验终端后不要假定补丁仍然有效。

原始转储与完整跟踪只保存在本地；分享日志前检查其中的个人安装路径。当前仅验证单台 RTX 5080 / NVIDIA 616.64，其他环境及长时间运行仍待验证。
