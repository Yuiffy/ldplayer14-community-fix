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

完整操作及回退说明：[安装指南](docs/INSTALL.zh-CN.md)。已验证版本为 LD14 14.0.26.1，但最终以两个文件的 SHA256 和运行时代码校验为准。

修补只作用于选定实例的当前进程，不覆盖磁盘 DLL。正常退出，再从原来的雷电入口启动即可回退。以后每次重启都需要重新通过修补启动器应用。

## 参与测试

2026-09-06 新增 [NVIDIA 线程退出清理原型](experimental/README.zh-CN.md)，只支持已验证的 NVIDIA 616.64 文件。原型在 `experimental` 目录，需另外安装 Frida 并显式启用；它不在现有信号量 ZIP 中，也不会由原启动器自动应用。

完整仓库现支持[两个修复的长期后台守护](experimental/README.zh-CN.md#长期运行两个修复)：无自动到期时间，跟随指定实例重启，可安装当前用户登录启动。用 `Check-LD14-Guard.cmd` 查看状态、`Stop-LD14-Guard.cmd` 停止。此模式仍为版本限定的实验修复。

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
