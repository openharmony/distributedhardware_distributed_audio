# 分布式音频指引

## 项目定位

本仓库对应 OpenHarmony `foundation/distributedhardware/distributed_audio`，实现跨设备音频协同使用能力（Speaker播音、Mic录音）。分布式音频不直接向应用提供接口，应用通过音频框架接口调用，使用方式与本地音频一致。

### 核心概念

- **主控端（Source）**：分布式音频控制端设备，向被控端发送指令，实现远程音频播放和录制
- **被控端（Sink）**：分布式音频被控端设备，接收主控端指令，提供本地音频外设供主控端使用
- **Speaker（播音设备）**：音频播放设备，dhId=1，Source端编码发送，Sink端解码播放
- **Mic（录音设备）**：音频采集设备，dhId=134217729，Sink端编码发送，Source端解码接收

### 架构层次

```
应用层 → 音频框架 → 分布式音频驱动 → 分布式音频服务 → SoftBus → 远端设备
```

## 目录结构详解

### 核心目录

- `audiohandler/`：硬件信息上报、设备状态通知，由分布式硬件管理框架加载
- `services/audiomanager/`：Source/Sink双端服务管理，SA入口和设备管理器
  - `managersource/`：主控端管理器（DAudioSourceManager、DAudioSourceDev）
  - `managersink/`：被控端管理器（DAudioSinkManager、DAudioSinkDev）
  - `servicesource/`：主控端服务（DAudioSourceService）
  - `servicesink/`：被控端服务（DAudioSinkService）
- `services/audioclient/`：Speaker/Mic客户端，与音频框架交互
  - `spkclient/`：Speaker客户端（DSpeakerClient）
  - `micclient/`：Mic客户端（DMicClient）
- `services/audiotransport/`：数据传输组件
  - `audioctrltransport/`：控制通道（DAudioSourceCtrlTrans、DAudioSinkCtrlTrans）
  - `senderengine/`：编码发送引擎（AVSenderEngineTransport）
  - `receiverengine/`：解码接收引擎（AVReceiverEngineTransport）
- `services/audiocontrol/`：音量、焦点、媒体键控制
  - `controlsource/`：主控端控制（DAudioSourceDevCtrlMgr）
  - `controlsink/`：被控端控制（DAudioSinkDevCtrlMgr）
- `services/audiohdiproxy/`：HDI代理，与驱动层交互（DAudioHdiHandler）
- `services/common/`：公共模块
  - `audioparam/`：音频参数定义（AudioParam、AudioEvent、AudioStatus）
  - `audioeventcallback/`：事件回调接口
  - `audiodata/`：音频数据结构
- `interfaces/inner_kits/native_cpp/`：IPC接口
  - `audio_source/`：主控端IPC（DAudioSourceProxy）
  - `audio_sink/`：被控端IPC（DAudioSinkProxy）

### 辅助目录

- `common/`：通用工具函数
- `sa_profile/`：System Ability配置
- `docs/knowledge/`：稳定背景知识文档
- `figures/`：架构图

## 核心架构

### 双端对称架构

| 角色 | SA服务 | 管理器 | 设备抽象 | 核心职责 |
| --- | --- | --- | --- | --- |
| Source（主控端） | DAudioSourceService | DAudioSourceManager | DAudioSourceDev | 发送指令、管理远端设备抽象 |
| Sink（被控端） | DAudioSinkService | DAudioSinkManager | DAudioSinkDev | 接收指令、提供本地音频外设 |

### 设备状态机

| 状态 | 枚举值 | 触发条件 | 允许操作 |
| --- | --- | --- | --- |
| STATUS_IDLE | 0 | 初始化/销毁完成 | EnableDevice |
| STATUS_READY | 1 | SetUp完成 | Start |
| STATUS_START | 2 | Start完成 | Pause/Stop |
| STATUS_STOP | 3 | Stop完成 | Restart/Release |

状态锚点：`services/common/audioparam/audio_status.h:21-26`

### 事件驱动模型

所有状态变化通过AudioEvent触发，事件编号规则：

| 分类 | 编号范围 | 关键事件 |
| --- | --- | --- |
| 控制通道 | 1-8 | OPEN_CTRL(1), CTRL_OPENED(3), CLOSE_CTRL(2), CTRL_CLOSED(4) |
| Speaker设备 | 11-17 | OPEN_SPEAKER(11), SPEAKER_OPENED(13), CLOSE_SPEAKER(12) |
| Mic设备 | 21-27 | OPEN_MIC(21), MIC_OPENED(23), CLOSE_MIC(22) |
| 音量控制 | 31-36 | VOLUME_SET(31), VOLUME_CHANGE(33) |
| 音频焦点 | 41-42 | AUDIO_FOCUS_CHANGE(41) |
| 参数设置 | 51-53 | SET_PARAM(51) |
| 编解码错误 | 61-62 | AUDIO_ENCODER_ERR(61), AUDIO_DECODER_ERR(62) |
| MMAP模式 | 81-86 | MMAP_SPK_START(81), MMAP_MIC_START(83) |

事件枚举锚点：`services/common/audioparam/audio_event.h:23-76`

### 双通道传输架构

| 通道类型 | 职责 | 实现模块 | 建立时机 |
| --- | --- | --- | --- |
| 控制通道 | 事件指令传输 | DAudioCtrlTrans | 设备启用时首先建立 |
| 数据通道 | 音频流传输 | AVEngineTransport | 控制通道建立后建立 |

**顺序约束**：必须先建立控制通道（收到CTRL_OPENED），再建立数据通道。

## 构建和验证

### 构建命令

从OpenHarmony源码根目录执行：

```sh
./build.sh --product-name rk3568 --build-target distributed_audio --ccache
```

### 测试要求

- 涉及真实设备组网的测试需要两台设备在同一局域网
- 提交使用 `git commit -s`
- 测试锚点：`services/test_example/` 和各模块 `test/` 子目录

### 测试用例索引

| 模块 | 测试类 | 锚点 |
| --- | --- | --- |
| Source服务 | DAudioSourceServiceTest | `services/audiomanager/test` |
| Sink服务 | DAudioSinkServiceTest | `services/audiomanager/test` |
| Source管理器 | DAudioSourceManagerTest | `services/audiomanager/test` |
| Sink管理器 | DAudioSinkManagerTest | `services/audiomanager/test` |
| Source设备 | DAudioSourceDevTest | `services/audiomanager/test` |
| Sink设备 | DAudioSinkDevTest | `services/audiomanager/test` |
| Speaker设备 | DSpeakerDevTest / DSpeakerClientTest | `services/audioclient/test` |
| Mic设备 | DMicDevTest / DMicClientTest | `services/audioclient/test` |
| 控制通道 | DAudioSourceCtrlTransTest / DAudioSinkCtrlTransTest | `services/audiotransport/test` |
| 发送引擎 | AVSenderEngineTransportTest | `services/audiotransport/test` |
| 接收引擎 | AVReceiverEngineTransportTest | `services/audiotransport/test` |
| HDI代理 | DAudioHdiHandlerTest | `services/audiohdiproxy/test` |
| IPC代理 | DAudioSourceProxyTest / DAudioSinkProxyTest | `interfaces/inner_kits/native_cpp/test` |

## 知识索引

稳定背景知识放在 `docs/knowledge/`。改动前按场景读取对应文件：

| 场景 | 先读 |
| --- | --- |
| 新增/修改设备启用流程 | `docs/knowledge/audio-device-lifecycle.md` |
| 修改Source/Sink服务交互 | `docs/knowledge/audio-source-sink-architecture.md` |
| 新增事件类型或处理逻辑 | `docs/knowledge/audio-event-pipeline.md` |
| Speaker/Mic差异化处理 | `docs/knowledge/audio-device-taxonomy.md` |
| 修改传输或编解码逻辑 | `docs/knowledge/audio-transport-pipeline.md` |

## 关键类和接口索引

### 核心管理类

| 类名 | 职责 | 锚点 |
| --- | --- | --- |
| DAudioSourceService | 主控端SA服务入口 | `services/audiomanager/servicesource/daudio_source_service.h` |
| DAudioSinkService | 被控端SA服务入口 | `services/audiomanager/servicesink/daudio_sink_service.h` |
| DAudioSourceManager | 主控端设备管理器 | `services/audiomanager/managersource/daudio_source_manager.h` |
| DAudioSinkManager | 被控端设备管理器 | `services/audiomanager/managersink/daudio_sink_manager.h` |
| DAudioSourceDev | 主控端设备抽象（基类） | `services/audiomanager/managersource/daudio_source_dev.h` |
| DSpeakerDev | Speaker主控端实现 | `services/audiomanager/managersource/dspeaker_dev.h` |
| DMicDev | Mic主控端实现 | `services/audiomanager/managersource/dmic_dev.h` |
| DAudioSinkDev | 被控端设备抽象 | `services/audiomanager/managersink/daudio_sink_dev.h` |

### 传输和编解码类

| 类名 | 职责 | 锚点 |
| --- | --- | --- |
| DAudioSourceCtrlTrans | 主控端控制通道传输 | `services/audiotransport/audioctrltransport/daudio_source_ctrl_trans.h` |
| DAudioSinkCtrlTrans | 被控端控制通道传输 | `services/audiotransport/audioctrltransport/daudio_sink_ctrl_trans.h` |
| AVSenderEngineTransport | 音频编码发送引擎 | `services/audiotransport/senderengine/av_sender_engine_transport.h` |
| AVReceiverEngineTransport | 音频解码接收引擎 | `services/audiotransport/receiverengine/av_receiver_engine_transport.h` |

### 控制和客户端类

| 类名 | 职责 | 锚点 |
| --- | --- | --- |
| DAudioSourceDevCtrlMgr | 主控端控制管理器 | `services/audiocontrol/controlsource/daudio_source_dev_ctrl_mgr.h` |
| DAudioSinkDevCtrlMgr | 被控端控制管理器 | `services/audiocontrol/controlsink/daudio_sink_dev_ctrl_mgr.h` |
| DSpeakerClient | Speaker被控端客户端 | `services/audioclient/spkclient/dspeaker_client.h` |
| DMicClient | Mic被控端客户端 | `services/audioclient/micclient/dmic_client.h` |

### HDI和IPC接口

| 类名 | 职责 | 锚点 |
| --- | --- | --- |
| DAudioHdiHandler | HDI代理处理类 | `services/audiohdiproxy/include/daudio_hdi_handler.h` |
| DAudioSourceProxy | 主控端IPC代理 | `interfaces/inner_kits/native_cpp/audio_source/include/daudio_source_proxy.h` |
| DAudioSinkProxy | 被控端IPC代理 | `interfaces/inner_kits/native_cpp/audio_sink/include/daudio_sink_proxy.h` |

## IPC调用链

| 场景 | Source端调用 | Sink端响应 | 事件流向 |
| --- | --- | --- | --- |
| 启用设备 | RegisterDistributedHardware | SubscribeLocalHardware | Source → Sink |
| 禁用设备 | UnregisterDistributedHardware | UnsubscribeLocalHardware | Source → Sink |
| 状态通知 | DAudioNotify | DAudioNotify | 双向对称 |

IPC代理锚点：`interfaces/inner_kits/native_cpp/audio_source/daudio_source_proxy.h` / `audio_sink/daudio_sink_proxy.h`

## 数据流向

### Speaker播放流程（Source → Sink）

```
[Source端]
AudioRenderer回调 → FeedAudioData → SenderEngine编码 → SoftBus传输
    ↓
[Sink端]
ReceiverEngine接收 → OnDecodeTransDataDone → dataQueue → PlayThread播放
```

### Mic录音流程（Sink → Source）

```
[Sink端]
AudioCapturer采集 → OnReadData → SenderEngine编码 → SoftBus传输
    ↓
[Source端]
ReceiverEngine接收 → OnDecodeTransDataDone → 本地音频框架
```

## 项目约束

### 架构约束

- **事件驱动优先**：所有状态变化必须通过AudioEvent触发，禁止直接调用内部方法。避免状态不一致。
- **双端对称设计**：Source端和Sink端的事件处理必须对称，编号规则一致（Speaker事件11-17，Mic事件21-27）。
- **控制通道先建**：数据传输前必须先建立控制通道（CTRL_OPENED），否则数据通道无法正常工作。

### 线程安全约束

- **锁获取顺序**：锁获取顺序：devMapMtx → ioDevMtx → dataQueueMtx。反向获取会导致死锁。
- **HDI回调异步**：HDI回调在驱动线程执行，禁止直接操作服务状态，必须通过EventHandler转发。
- **事件处理异步**：所有事件必须经过EventHandler异步处理，禁止在回调线程直接处理。

### 启动顺序约束

1. Sink服务启动（被控端先启动，等待指令）
2. Source服务启动（主控端后启动，主动发起）
3. Source初始化（加载AVEngineProvider）
4. Sink初始化（加载AVEngineProvider）

**顺序错误**：Source先启动而Sink未就绪会导致IPC调用失败。

## 反模式/修改前检查

### 设备生命周期

- **禁止**在设备未完全启用时调用Start。检查AudioStatus是否为STATUS_READY。
- **禁止**跳过控制通道直接建立数据通道。检查CTRL_OPENED事件是否已收到。
- **禁止**在销毁流程中遗漏UnRegisterAudioDevice。检查HDF驱动是否已移除。
- **禁止**直接删除audioDevMap中的设备对象。必须通过EventHandler异步删除。

### 事件处理

- **禁止**新增事件类型时使用已有编号。Speaker用11-17，Mic用21-27，避免编号冲突。
- **禁止**在回调线程（OnCtrlTransEvent）直接修改设备状态。必须通过EventHandler转发。
- **禁止**遗漏事件处理函数注册。检查memberFuncMap_是否包含新事件类型。
- **禁止**发送未定义的事件类型。检查AudioEventType枚举是否包含。

### 设备类型处理

- **禁止**混淆Speaker和Mic的事件编号。Speaker用11开头，Mic用21开头。
- **禁止**在Speaker路径使用SenderEngine（Source端应为Mic专用）。检查引擎类型是否匹配数据流向。
- **禁止**在Mic路径使用ReceiverEngine（Source端应为Speaker专用）。
- **禁止**遗漏dhId判断逻辑。修改设备处理代码时必须检查dhId值。

### 传输管道

- **禁止**跳过控制通道直接建立数据通道。检查IsOpened()返回true后再建立数据通道。
- **禁止**在编码线程直接操作AudioRenderer/AudioCapturer。必须通过回调异步处理。
- **禁止**修改FeedAudioData的数据格式。必须匹配AudioParam中定义的codecType。
- **禁止**遗漏dataQueue的线程安全保护。dataQueueMtx必须保护dataQueue操作。

### IPC调用

- **禁止**直接调用远端服务的内部方法。必须通过IPC Proxy（DAudioSourceProxy/DAudioSinkProxy）。
- **禁止**在Source端未初始化SinkProxy时调用RegisterDistributedHardware。检查sinkServiceMap是否包含目标设备。
- **禁止**跳过DAudioNotify直接发送事件。必须通过IPC通道保证可靠性。
- **禁止**在崩溃恢复中遗漏清理audioDevMap。检查对应devId的条目是否已移除。

## 常见问题和调试技巧

### 设备启用失败

**症状**：调用EnableDevice返回失败

**排查步骤**：
1. 检查Sink服务是否已启动：`ps -ef | grep daudio_sink_service`
2. 检查控制通道是否建立成功：查看日志中CTRL_OPENED事件
3. 检查HDF驱动是否注册成功：`ls /dev/audio/` 查看分布式音频设备节点
4. 检查AudioParam参数是否正确：对比Source端和Sink端的AudioParam

**关键日志关键字**：`"SetUp"`, `"CTRL_OPENED"`, `"RegisterAudioDevice"`

### 音频播放无声音

**症状**：设备启用成功但播放无声音

**排查步骤**：
1. 检查数据通道是否建立：查看SenderEngine和ReceiverEngine日志
2. 检查编解码是否正常：查看AUDIO_ENCODER_ERR和AUDIO_DECODER_ERR事件
3. 检查AudioRenderer是否启动：`"StartRender"` 日志
4. 检查音量设置：VOLUME_SET事件是否发送成功

**关键日志关键字**：`"FeedAudioData"`, `"OnDecodeTransDataDone"`, `"StartRender"`

### IPC调用超时

**症状**：RegisterDistributedHardware或DAudioNotify超时

**排查步骤**：
1. 检查对端服务是否存活：`ps -ef | grep daudio`
2. 检查网络连接：`ping` 对端设备
3. 检查SoftBus连接状态：SoftBus日志
4. 检查SA注册是否成功：`sa_manager -l` 查看服务列表

**关键日志关键字**：`"RegisterDistributedHardware"`, `"DAudioNotify"`, `"OnRemoteDied"`

### 设备状态不一致

**症状**：audioDevMap中残留已销毁的设备对象

**排查步骤**：
1. 检查DisableDevice流程是否完整执行
2. 检查DeathRecipient是否正常清理：`OnRemoteDied` 日志
3. 检查事件处理是否遗漏：memberFuncMap_ 是否包含所有事件
4. 检查EventHandler是否阻塞：事件队列是否积压

**关键日志关键字**：`"DeleteAudioDevice"`, `"ClearAudioDev"`, `"OnRemoteDied"`

## 性能优化建议

### 音频传输延迟优化

- 使用MMAP模式减少数据拷贝（事件编号81-86）
- 调整AudioParam中的bufferSize以平衡延迟和稳定性
- 编解码选择低延迟codecType（如AAC_LC）

### 内存优化

- 复用AudioData缓冲区，避免频繁分配释放
- 控制dataQueue大小，避免积压过多数据
- 及时释放已完成的设备对象

### 线程优化

- 避免在关键路径加锁，使用无锁队列
- EventHandler事件处理优先级调优
- 编解码线程绑定到大核

## 错误码索引

| 错误码 | 说明 | 处理建议 |
| --- | --- | --- |
| ERR_DH_AUDIO_HDF_FAIL | HDF通用失败 | 检查HDF驱动状态 |
| ERR_DH_AUDIO_HDF_INVALID_OPERATION | 无效操作 | 检查设备状态是否允许该操作 |
| ERR_DH_AUDIO_SA_FAIL | SA服务失败 | 检查SA服务是否正常启动 |
| ERR_DH_AUDIO_NULLPTR | 空指针错误 | 检查对象初始化流程 |

错误码定义锚点：`common/include/daudio_errorcode.h`

## 相关文档

- [音频框架](https://gitee.com/openharmony/multimedia_audio_framework)
- [分布式硬件管理框架](https://gitee.com/openharmony/distributedhardware_distributed_hardware_fwk)
- [设备管理](https://gitee.com/openharmony/distributedhardware_device_manager)