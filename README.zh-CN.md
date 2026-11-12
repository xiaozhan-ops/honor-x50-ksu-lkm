# 荣耀 X50（ALI-AN00）：锁定 bootloader 下的 KernelSU LKM 移植

[English](README.md) | **简体中文**

针对荣耀 X50（ALI-AN00 / ALI-TN00）的**可用 KernelSU 内核模块（LKM）移植**，以及在
该机型 bootloader 无法解锁的前提下，把模块加载进去所需的提权链。

移植才是主体。[`port/`](port/) 把一次性的 uid 0 变成：授权应用可用的 `su`、能真正与内核
通信的 Manager、以及按应用授权 —— 跑在一个没有对应源码发布、且大量 KernelSU 所需符号
并未导出的厂商内核（5.10.236）上。工程细节见 [docs/LKM-PORT.md](docs/LKM-PORT.md)。

提权是使能手段：CVE-2026-43499，内核 `rtmutex` `remove_waiter` 路径上的 use-after-free，
用于取得一次受控的 8 字节写，随后把 `cred` 换成 `init_cred`。

两个 target profile 中的内核地址偏移都是**从本机自己的 boot 镜像**测出来的，不是从别的
机型抄来的。

## 仓库结构

| 路径 | 是什么 |
| :--- | :--- |
| [`port/`](port/) | **KernelSU LKM 移植**：补丁、构建脚本、主机侧与设备侧工具、allowlist 生成器 |
| [`docs/LKM-PORT.md`](docs/LKM-PORT.md) | 移植怎么工作，以及最费时的那两个坑 |
| [`exploit/`](exploit/) | CVE-2026-43499 的利用链与两个 X50 target profile |
| [`docs/`](docs/) | 偏移来源、AN/TN 对比、验证记录 |

## 移植难在哪

即使不打算运行，也值得一读：

* 91 个内核符号在运行时解析：83 个函数走裸汇编跳板，8 个是数据符号。直觉写法的 C 函数指针宏能编译通过、能通过
  所有不需要真机的测试，但**会让设备硬复位**：编译器生成的间接调用携带 CFI 类型哈希，
  荣耀的 HISEC 会把它当成攻击。
* 这个内核的 `sys_call_table` 指向 `.cfi_jt` 垫片，而不是 `__arm64_sys_ni_syscall`，
  所以常规的"找一个空槽位"扫描一个都找不到。
* 把 `sys_enter` tracepoint 注册到结构体的本地副本上，会成功、返回 0、并且永远不触发。
  钩子必须挂在真实符号上。
* `track_throne()` 在模块 init 里跑会复位设备，放进 workqueue 就正常。

root 依然是**一次性的（每次开机重来）**：cred 替换和内核模块都只活在内存里。
[`port/host/restore.ps1`](port/host/restore.ps1) 会重跑整条链，且必须在开机后约一分钟内启动。

## 机型与档案

| Profile | 机型 | 固件 | 内核 |
| :--- | :--- | :--- | :--- |
| `annap-ALI-AN00_9.0.0.220` | 荣耀 X50（ALI-AN00） | MagicOS 9.0.0.220，build CNC00E206R9P4 | `5.10.236-android12-9-gf68ed03ce0d2` |
| `annap-ALI-TN00_9.0.0.230` | 荣耀 X50（ALI-TN00） | MagicOS 9.0.0.230 | `5.10.236-android12-9-g4b262e5255ed` |

偏移是用 `kallsyms.c` 从各自 boot dump 里切出来的 kernel Image 上提取的（各 140,046 个符号）。

**请选与设备实际固件匹配的 profile。** 两者的差异正好在最要紧的地方：exploit 读取的 16 个
内核符号里有 11 个相同，但整个 `sched_class` 组偏移了 `0x200`，这会移动
`SLIDE_RT_SCHED_CLASS_OFF` —— 也就是写进 `fake_task->sched_class`、用来化解
`check_class_changed()` 的那个值。用错档案会在 `rt_mutex_setprio` 尾部留下一次野指针调用。

动手前先确认自己在哪个固件上：

```bash
adb shell getprop ro.build.display.id
adb shell uname -a
```

固件版本字符串**无法**从 boot 镜像内部恢复 —— 两份 dump 里都没有 `build.prop`、`MagicOS`
或 `ALI-*` 字符串。上面的版本标签依据的是 dump 的来源；内核哈希是实测的。

## 构建

需要 Android NDK。两个 profile 用 r29 均可干净构建：

```bash
cd exploit
NDK_ROOT=/path/to/android-ndk make PROJECT=annap-ALI-AN00_9.0.0.220 bin
NDK_ROOT=/path/to/android-ndk make PROJECT=annap-ALI-TN00_9.0.0.230 bin
```

每个 profile 的产物在 `exploit/build/<PROJECT>/bin/` 下：

| 文件 | 大小 | 用途 |
| :--- | :--- | :--- |
| `exploit` | 约 65 KB | PIE 动态链接，通过 `adb shell` 运行 |
| `exploit_static` | 约 2.2 MB | 完全静态 bionic，自包含 |

Makefile 会自行探测 NDK host tag（`windows-x86_64`、`darwin-x86_64`、`linux-x86_64`），
不假定 Linux，所以在 Windows 上不需要额外参数。

## 运行

root 是运行时产生的，顺序不能反：先提权，再加载模块。

### X50

X50 走 [`port/`](port/) 里的外部模块方案。Windows 上：

```powershell
powershell -File port/host/restore.ps1 -Payload E:\payload
```

它会自己重启卡进 exploit 的时间窗、跑完整条链、加载 `kernelsu.ko`，失败自动重试。
如果已经有 shell 身份（adb shell、Shizuku、Termux + adb），也可以在设备上直接跑：

```sh
sh /data/local/tmp/restore_ondevice.sh
```

两者都要求 payload 目录（或 `/data/local/tmp`）里有 `gl_root`、`ksu_ctrl.ko`、`ksud`、
`ksu_loader.sh`。整条链必须在开机后约一分钟内启动——这正是 `restore.ps1` 自己负责重启的原因。

之后：

```bash
adb shell /data/local/tmp/kbin/su -c id
```

## 哪些验证过，哪些没有

**在本机实测**（见 [docs/](docs/)）：

- exploit 读取的全部 16 个内核符号，按 profile 分别验证
- `CONFIG_FUTEX_PI=y` —— CVE-2026-43499 唯一要求的内核配置，所以本机在影响范围内
- `CONFIG_MODULE_SIG_FORCE=y` —— 这就是为什么整条链要在 `init_module` 之前把
  `sig_enforce` 翻成 0，之后再还原
- `CONFIG_CFI_CLANG=y`，非 permissive
- 两个 profile 都能编译，且每次构建都解析到自己的偏移

**未验证：**

- **结构体布局偏移。** kallsyms 解析的是内核地址，不携带类型信息，所以 `FAKE_TASK_*`
  （包括 UAF 留下悬挂引用的 `pi_blocked_on`）、`WAITER_*`、`TASK_CRED_OFF`、
  `MM_OWNER_OFF`，以及 `random_table + 0x100` 的 boot_id 表项偏移，都是从参考 profile
  继承来的，**未在本机确认**。每一项都在 `target.h` 里就地标注。
- **ALI-AN00 的 `SLIDE_RT_SCHED_CLASS_OFF`** 是推导值（`rt_sched_class - 0x500`），
  不是实测值。`0x500` 这个关系在另一个 profile 上得到确认；如果运行在
  `check_class_changed()` 处 panic，先重新推导这一项。
- **逐项验证。** 整条链已经在 ALI-AN00 / MagicOS 9.0.0.220 上反复跑通：走到了 cred 写，
  `getuid()` 返回 0，`kernelsu.ko` 加载成功，Manager 显示运行中。这端到端地锻炼了每一个
  偏移，但没有逐项钉死 —— 只有 `mm->owner` 和 `task->comm` 被 VERIFY 阶段显式检查。
- **Manager 的"需要更新内核"红条。** 把 `KSU_VERSION` 固定之后，Manager 已经显示模块在
  工作，但顶部仍挂着要求更新内核的红条。这一点没有查到底；uapi 版本（这里是 2）是最可能的
  不匹配点。

## 文档

- **[docs/LKM-PORT.md](docs/LKM-PORT.md)** —— 移植工程记录：CFI 与函数指针 shim、`.cfi_jt`
  垫片、tracepoint 副本陷阱、延迟 throne 扫描、allowlist 格式
- **[port/README.md](port/README.md)** —— 构建、授权、设备侧与主机侧工具
- **[docs/ALI-AN00-TN-COMPARISON.md](docs/ALI-AN00-TN-COMPARISON.md)** —— 两份 boot 镜像
  逐符号对比、`sched_class` 位移、构建验证与复现步骤
- **[docs/ALI-AN00-VERIFICATION.md](docs/ALI-AN00-VERIFICATION.md)** —— 提取流程与每个偏移的来源
- **[docs/ALI-AN00-SYMBOLS.txt](docs/ALI-AN00-SYMBOLS.txt)** —— 两次 boot 的实测符号表，加相关
  kernel config
- **[docs/cmp_boots.py](docs/cmp_boots.py)** —— 可复现的两次 boot 对比

## 为什么要自备 .ko 和 loader

`CONFIG_MODULE_SIG_FORCE=y` 意味着运行期的 `sig_enforce` 开关会拦截未签名模块加载。
exploit 在加载前把它翻成 0，loader 脚本在模块进内核后再还原成 1。

荣耀还从 `/proc/kallsyms` 里剔除了 `commit_creds` 等符号，所以内核 loader 无法解析
`.ko` 的未定义符号。流程里 bind-mount 了一份伪造的 kallsyms，把被剔除的符号按真实运行地址
（链接地址 + KASLR slide）补在最前面。

GKI 的结构体布局也与荣耀的不同，所以原版 GKI 的 `android12-5.10_kernelsu.ko` 不能用。
[`port/`](port/) 会针对与固件 sublevel 匹配的 MagicOS 内核源码、以及本机内核 config 重新构建
KernelSU v3.3.0。

## 致谢

X50 的 target profile 与 exploit 适配来自 **a23bc** 的 ALI-AN00
移植，本次工作是在其基础上克隆展开的。[`port/`](port/) 下的 LKM 移植及其文档由本次
工作新增。

该移植建立在 [yakidango-official/GhostLock-H80GT](https://github.com/yakidango-official/GhostLock-H80GT)
的 exploit 与 target 框架之上，后者又源自：

- [NebuSec/CyberMeowfia — IonStack / CVE-2026-43499](https://github.com/NebuSec/CyberMeowfia)
  （最初的公开 exploit；rtmutex UAF 由 Nebula Security 的 VEGA 发现，上游修复提交
  `3bfdc63936dd`，落于 Linux 7.1）
- [BuSung-dev/CVE-2026-43499-S25U](https://github.com/BuSung-dev/CVE-2026-43499-S25U)
- [F-19-F/IonStackQuest3](https://github.com/F-19-F/IonStackQuest3)
- [KernelSU](https://github.com/tiann/KernelSU)
- [Magisk](https://github.com/topjohnwu/Magisk)

X50 profile 里的结构体布局偏移沿用自参考项目的 80 GT profile。本项目复用的提取流程
（`kallsyms.c`）也出自那里。完整来源见 [NOTICE](NOTICE)。

## 署名

本项目由 **DeepSeek-V4.1-Flash** 提供。

## 许可

- 仓库中的 exploit 与工具（`exploit/`、顶层 `docs/`）为 **Apache License 2.0**
  （见 [LICENSE](LICENSE)），与本移植所源自的上游项目一致。
- 补丁与构建脚本为 **GPL-2.0**：许可证全文见 [`port/LICENSE-GPL-2.0`](port/LICENSE-GPL-2.0)。
- [`port/kernelsu-3.3.0-honor-5.10.226.patch`](port/) 是对该 GPL-2.0 代码树的补丁，因此
  同样是 **GPL-2.0**。`port/build.sh` 与 `port/fix-versions.py` 以相同条款发布，使模块构建
  处于同一许可之下。`port/` 其余部分（主机侧与设备侧工具）为 Apache-2.0。
- 分发编译好的 `kernelsu.ko` 时，GPL-2.0 要求你向接收方提供对应源码 —— 即 KernelSU v3.3.0
  加上本补丁。

## 警告

仅供对**自有设备**的安全研究。运行它会通过一个 UAF 修改内核内存；一次失败的尝试会让手机
重启。root 意味着对设备的完全控制。刷机、写分区、以及 root 后关闭各种防护，不在本工具的
覆盖范围内，且可能永久变砖。

请使用与你的固件匹配的 profile。两个 X50 profile 里都有若干结构体偏移继承自另一台荣耀机型，
并在头文件中标记为 `UNVERIFIED`；错误的值不会大声失败，它要么在链中途静默死亡，要么把
cred 指针写到不该写的地方。先确认固件：

```bash
adb shell getprop ro.build.display.id
adb shell uname -a
```

这里的 root 在设计上就是临时的：cred 替换和内核模块都只存在于内存中，重启即全部消失。
不存在持久化安装，且在 bootloader 未解锁的情况下也不可能实现。
