# 分布式音频指引

## 项目定位

本仓库对应 OpenHarmony `foundation/distributedhardware/distributed_audio`，实现跨设备音频协同使用能力（Speaker播音、Mic录音）。优先按这些目录定位问题：

- `audiohandler/`：硬件信息上报、设备状态通知，由分布式硬件管理框架加载。
- `services/audiomanager/`：Source/Sink双端服务管理，SA入口和设备管理器。
- `services/audioclient/`：Speaker/Mic客户端，与音频框架交互完成播放/采集。
- `services/audiotransport/`：数据传输组件，编码/解码引擎和控制通道。
- `services/audiohdiproxy/`：HDI代理，与驱动层交互。

## 构建和验证

构建命令从 OpenHarmony 源码根目录执行，不在本子目录执行。

```sh
./build.sh --product-name rk3568 --build-target distributed_audio --ccache
```

涉及真实设备组网的测试需要两台设备在同一局域网。提交使用 `git commit -s`。

## 知识索引

稳定背景知识放在 `docs/knowledge/`。改动前按场景读取对应文件：

| 场景 | 先读 |
| --- | --- |
| 新增/修改设备启用流程 | `docs/knowledge/audio-device-lifecycle.md` |
| 修改Source/Sink服务交互 | `docs/knowledge/audio-source-sink-architecture.md` |
| 新增事件类型或处理逻辑 | `docs/knowledge/audio-event-pipeline.md` |
| Speaker/Mic差异化处理 | `docs/knowledge/audio-device-taxonomy.md` |
| 修改传输或编解码逻辑 | `docs/knowledge/audio-transport-pipeline.md` |

## 项目约束

- **事件驱动优先**：所有状态变化必须通过AudioEvent触发，禁止直接调用内部方法。避免状态不一致。
- **双端对称设计**：Source端和Sink端的事件处理必须对称，编号规则一致（Speaker事件11-17，Mic事件21-27）。
- **控制通道先建**：数据传输前必须先建立控制通道（CTRL_OPENED），否则数据通道无法正常工作。
- **线程安全锁顺序**：锁获取顺序：devMapMtx → ioDevMtx → dataQueueMtx。反向获取会导致死锁。
- **HDI回调异步**：HDI回调在驱动线程执行，禁止直接操作服务状态，必须通过EventHandler转发。