# 雷电 14 社区诊断与实验修补

面向 LDPlayer 14 长时间运行时的内存、句柄增长问题，保存可复查的诊断结论、最小修补和测试工具。

**当前预发布版只修补一处已验证的信号量泄漏。大额内存增长已确认一条驱动线程退出清理失配路径，实验补丁通过短时 A/B/A 对照，真实游戏长期效果仍待测试；黑屏未证明已修复。**

这是用户维护的社区项目，与雷电官方及 NVIDIA 无隶属关系。

| 问题 | 当前状态 |
| --- | --- |
| `MyRenderThread` 析构漏关第一个信号量 | 已定位；本地修补通过原生及实时验证 |
| 长期私有提交增长到几十 GiB | 已定位主要空页保留机制；实验清理短时有效，长期待验证 |
| 显示器短时黑屏 / 驱动恢复 | 尚不能确认与每次内存增长的因果关系 |
| 其他 LD14 版本、其他 GPU / 驱动组合 | 未验证；文件校验不匹配时拒绝应用 |

## 开始使用

1. 从 [Releases](https://github.com/Yuiffy/ldplayer14-community-fix/releases) 下载预发布 ZIP，完整解压。
2. 安装 64 位 Python 3.10 或更新版本，包括 `py.exe` Launcher。
3. 双击 `Setup-LD14-Fix.cmd`，选择自己的 LD14 安装目录和实例编号。
4. 双击 `Start-LD14-Fixed.cmd` 启动并修补。用 `Check-LD14-Fix.cmd` 确认 `after: patched`。

完整操作及回退说明：[安装指南](docs/INSTALL.zh-CN.md)。支持 LD14 14.0.26.1 和 [14.0.31.0](docs/LD14-14031.md) 的两组指定文件，最终以 renderer / fastpipe2 的完整 SHA256 配对和运行时代码校验为准。14.0.31.0 已通过结构、原生片段与现场启用检查，长期游戏效果仍需观察。

修补只作用于选定实例的当前进程，不覆盖磁盘 DLL。单次启动器模式下，每次重启需要重新应用。启用下述后台守护后，守护会在所选实例每次启动时重新校验并自动应用；需要回退时先停止守护，再正常退出实例。

## 参与测试

新增的 [NVIDIA 线程退出清理原型](experimental/README.zh-CN.md) 支持已验证的 NVIDIA **616.64 / 616.92** 文件，按完整 SHA256 选择各自的地址配置。616.92 已通过[新版驱动对照验证](docs/NVIDIA-61692.md)，长期游戏效果仍待观察。原型在 `experimental` 目录，需另外安装 Frida 并显式启用；它不在现有信号量 ZIP 中，也不会由原启动器自动应用。

完整仓库现支持[两个修复的长期后台守护](experimental/README.zh-CN.md#长期运行两个修复)：通过 Windows 计划任务独立运行，无自动到期时间，跟随指定实例重启，可安装当前用户登录启动。用 `Check-LD14-Guard.cmd` 查看状态、`Stop-LD14-Guard.cmd` 停止并暂停任务、`Start-LD14-Guard.cmd` 恢复。此模式仍为版本限定的实验修复。

新版包含 [Frida USB 依赖崩溃保护](docs/FRIDA-USB-CRASH.md)。更新后运行一次 `Start-LD14-Guard.cmd` 即可替换旧守护，更新本身无需重启雷电；状态中应有 `frida_usb_guard.active: true`。

升级至 NVIDIA 616.92 后，先更新完整仓库，再运行 `Start-LD14-Guard.cmd`。当前守护标记为 `LD14-DUAL-FIX-GUARD-5`，会替换仍在运行的旧版控制器并加载 LD14 14.0.31.0 适配；启用时显示 `driver_version: 616.92`，未知驱动仍会拒绝应用。

### 雷电升级后是否自动应用

后台守护会跟随已配置实例的进程退出和再次启动。升级后的 renderer / fastpipe2 文件配对、NVIDIA 驱动及运行时指令均在已验证配置内时，两个补丁会自动重新应用。没有变化的组件可继续使用原配置，不能仅按前端版本号判断兼容。

遇到未知文件或代码时，守护会保留错误并拒绝修改目标进程；它不会自动猜测新地址，也不会自动下载或执行远端代码。增加新版适配后，更新本地仓库并运行一次 `Start-LD14-Guard.cmd`，再用 `Check-LD14-Guard.cmd` 确认 `state: active`、`semaphore_patch: patched` 和 `nvidia_cleanup: true`。更换安装目录或实例编号需要重新配置。

按平时方式运行《碧蓝航线》或原来触发问题的负载，预热约 10 分钟后启动 `Record-LD14-Stats.cmd`。每分钟记录一次，默认 4 小时，可按 Ctrl+C 停止。

先比较 30-60 分钟，再看 2-4 小时。记录游戏所处阶段、应用重启以及卡顿/黑屏时间；不必刻意等内存涨到几十 GiB。将 `logs` 目录中的 CSV 和版本信息提交到 [Issues](https://github.com/Yuiffy/ldplayer14-community-fix/issues)。记录工具不会重启模拟器或清理内存。

句柄稳定不代表内存问题已经解决。已发生过修补后约 70 秒增加 334.98 MiB 私有提交、句柄反而减少的记录。

## 开发

```powershell
py -3 -m unittest discover -s tests -v
py -3 scripts/package.py
```

测试需要 Windows 64 位；无需安装雷电。安装可选 Frida 依赖后，原生清理测试只注入测试自身创建的临时子进程，没有 GPU 负载。发布包生成到 `dist`，只包含明确列出的源码、启动器、说明、许可证和校验文件。

- [诊断记录](docs/DIAGNOSIS.md)：确认缺陷、反证及尚未解决的线索。
- [后续工作](docs/ROADMAP.md)：长期验证和内存归属分析。
- [贡献说明](CONTRIBUTING.md)：复现、证据和修补验证要求。
- [版本记录](CHANGELOG.md)。

源码采用 [MIT 许可证](LICENSE)。项目和发布包不包含厂商二进制文件、本机实例配置或进程内存转储。
