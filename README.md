# Sys-Reference
这个仓库主要记录准备OS竞赛中收集的书籍，参考的论文和所记下的笔记等。这些资料主要包括ebpf性能监测，Linux网络，文件系统的配置调优，微服务系统的异常检测和故障定位、K8s集群等主题，是了解相关领域的一份不错的总结。

截止至2025-7-1，下面是各种资源列表

书籍列表如下：
| 名称 | 说明 | 
| ---- | ----- | 
| 循序渐进Linux（第2版） | 基础知识、服务器搭建、系统管理、性能调优、虚拟化与集群应用 |
| Learning eBPF Programming the Linux Kernel for Enhanced Observability, Networking, and Security | 介绍ebpf原理，以及介绍eBPF如何增强Linux内核的可观测性、网络和安全性，主要偏理论 |
| Linux性能优化大师 | 深入讲解Linux性能优化技巧 |
| 12-Linux性能优化实战 | 实战指南，提供具体的性能优化案例和方法 |
| Wireshark网络分析的艺术 | 网络分析工具Wireshark的使用艺术 |
| 性能之巅：洞悉系统、企业与云计算 | 全面解析系统、企业与云计算的性能问题 |
| Kubernetes in Action中文版 | Kubernetes在实际操作中的应用指南 |
| Linux程序设计(第4版) | Linux程序设计的基础和高级概念 |
| 文件系统技术内幕 | 探讨文件系统的内部工作原理和技术细节 |
| UNIX环境高级编程(第3版) | UNIX环境下的高级编程技巧和实践 |
| 深入理解LINUX网络技术内幕 | 对Linux网络技术的深入理解和剖析 |
| BPF之巅 洞悉Linux系统和应用性能 | 利用BPF技术深入理解Linux系统和应用性能，可以看作Learning eBPF的进阶篇，给出许多实践案例 |
| 深入剖析Kubernetes | 对Kubernetes的深入剖析和理解 |

---

论文列表如下：
| 名称 | 说明 | 
| ---- | ----- |
|Evolution of Aegis: Fault Diagnosis for AI Model Training Service in Production|  阿里云构建的面向AI训练的云上故障诊断与恢复系统     | 
| ART: A Unified Unsupervised Framework for Incident Management in Microservice Systems | [微服务系统无监督学习故障流程解决方案](https://metaso.cn/s/TWIZeDb) |
| Automated Reasoning and Detection of Specious Configuration in Large Systems with Symbolic Execution | 基于符号解析技术的自动配置推理 |
| Automatic Kernel Offload Using BPF | 提出了一个自动化方案来决定应用程序功能是否以及如何被卸载到内核，以提高系统的效率和性能，同时指出了实施该方案所涉及的一系列技术和理论挑战。| 
| CAPES: unsupervised storage performance tuning using neural network-based deep reinforcement learning | **基于深度强化学习的神经网络来进行存储性能优化的参数调整。传统的参数调整方法需要进行多次测试和微调，而CAPES可以在不需要人工干预的情况下自动找到最佳参数值，并在生产环境中收集数据并提供调整建议。** |
| Carver: Finding Important Parameters for Storage System Tuning | 统计方法降维，找出存储系统重要参数 | 
| CONFD: Analyzing Configuration Dependencies of File Systems for Fun and Profit | 深入研究了Ext4和XFS两个主要文件系统的配置相关问题，并发现了一种普遍存在的模式——多级配置依赖关系。基于此，他们开发了一个可扩展的工具CONFD来自动提取这些依赖关系，并创建了六个插件来解决不同类型的配置相关问题。 |
| Towards Better Understanding of Black-box Auto-Tuning: A Comparative Analysis for Storage Systems |提出了多种黑盒自动调优方法进行比较分析。通过在存储系统上进行实验，作者使用了近25,000个独特的配置和超过450,000个数据点的数据集进行了测试。结果表明，不同的硬件、软件和工作负载会导致最优配置的不同，而没有一种技术可以优于其他所有技术。 | 
| Computing load aware and long-view load balancing for cluster storage systems | 提出了一个成本高效的“计算负载感知和长期视角负载平衡”（CALV）方法。CALV不仅能够感知计算负载，还能够在长时间内实现负载平衡，通过在不同的时间周期内将贡献更多计算工作量的数据块迁移到更过载的服务器上，并将贡献较少计算工作量的数据块迁移到更未加载的服务器上来实现。 |
| EZIOTracer: unifying kernel and user space I/O tracing for data-intensive applications | 提出一种统一内核和用户空间I/O跟踪的方法，用于数据密集型应用程序。| 
| Failure Diagnosis in Microservice Systems: A Comprehensive Survey and Analysis | 微服务系统中的故障诊断提供了一个全面的综述和参考| 
| Falcon: A Practical Log-Based Analysis Tool for Distributed Systems | 设计了一个模块化的架构，可以无缝地组合多个不同的日志源并生成一个一致的空间时间图。为了保持事件因果关系的一致性，即使在收集来自不同未同步机器的日志时，Falcon也引入了新颖的发生之前符号表示法，并依赖于现成的约束求解器来获得一致的事件顺序。通过使用Apache Zookeeper等流行的分布式协调服务进行案例研究，作者证明了Falcon能够轻松分析复杂的分布式协议| 
| LogShrink: Effective Log Compression by Leveraging Commonality and Variability of Log Data | 提出了LogShrink方法，这是一种新颖且有效的方法，通过利用日志数据的共性和变异性来进行压缩。作者还提出了一种基于最长公共子序列和熵技术的分析器，用于识别日志消息中的潜在共性和变异性。| 
| MicroRank: End-to-End Latency Issue Localization with Extended Spectrum Analysis in Microservice Environments | MicroRank首先区分哪些跟踪是异常的，然后使用PageRank Scorer模块将正常和异常跟踪信息作为输入，并根据扩展频谱技术对不同跟踪的重要性进行差异分析。最后，频谱技术可以根据PageRank Scorer提供的加权频谱信息计算排名列表，更有效地定位根本原因。**可以参考实验设计**|
| Nahida: In-Band Distributed Tracing with eBPF | 该系统基于eBPF技术，可以在不侵入应用程序的情况下追踪完整的请求执行路径。现有的分布式跟踪系统存在一些限制，如侵入式仪器、跟踪丢失或不准确的跟踪关联等问题。相比之下，Nahida可以处理多线程应用程序，并且引入的开销很小 **参考测试设计**| 
| Network-Centric Distributed Tracing with DeepFlow: Troubleshooting Your Microservices in Zero Code | DeepFlow的网络中心分布式追踪框架，用于解决微服务中的性能问题。传统的性能监控解决方案在处理复杂的微服务时面临挑战，而DeepFlow通过网络中心追踪平面和隐式上下文传播提供了开箱即用的追踪功能，并消除了基础设施中的盲点，以低成本捕获网络指标并增强不同组件和层之间的相关性。| 
| Nezha: Interpretable Fine-Grained Root Causes Analysis for Microservices on Multi-modal Observability Data | 该方法可以对多模态可观测数据进行分析，并在代码区域和资源类型级别上定位故障的根本原因。为了实现这一目标，Nezha将异构的多模态数据转换为同质化的事件表示形式，并通过构建和挖掘事件图来提取事件模式。Nezha的核心思想是将故障发生前后的事件模式进行比较，以可解释的方式定位故障的根本原因。 | 
| One-Size-Fits-None: Understanding and Enhancing Slow-Fault Tolerance in Modern Distributed Systems | 探讨了现代分布式软件中慢故障容忍性的特点和现有实践，并提出了一个轻量级库ADR来增强系统的适应性| 
| Performance and Protection in the ZoFS User-space NVM File System |建立了一个基于coffer的NVM文件系统架构，以提高未修改动态链接的应用程序的性能，并促进高效灵活的用户空间NVM文件系统库的发展。 | 
| Real-Time Intrusion Detection and Prevention with Neural Network in Kernel Using eBPF | 基于神经网络和eBPF的实时入侵检测与预防方法。传统的入侵检测方法存在数据采集效率低、安全性能与性能平衡不足等问题。而将入侵检测和预防任务下放到扩展Berkeley Packet Filter（eBPF）中可以解决这些问题。本文重新设计了神经网络推理机制以解决eBPF的限制，并提出了一个线程安全的参数热更新机制，无需显式使用自旋锁。 | 
| TrackIops: Real-Time NFS Performance Metrics Extractor | 提出一种新的NFS文件系统ebpf插桩机制| 
| TrinityRCL: Multi-Granular and Code-Level Root Cause Localization Using Multiple Types of Telemetry Data in Microservice Systems | TrinityRCL利用三种类型的监控数据构建因果图，能够实现对应用程序级、服务级、主机级和指标级等多个层次的异常根本原因分析，并具有独特的代码级别定位能力。 | 
| Unsupervised Detection of Microservice Trace Anomalies through Service-Level Deep Bayesian Networks | 提出TraceAnomaly的无监督异常检测系统，用于检测微服务调用跟踪中的异常情况。该系统的创新点在于使用深度贝叶斯网络和后验流设计，通过机器学习自动学习正常的调用模式，并在线上实时检测新的异常情况。| 
| USAD: UnSupervised Anomaly Detection on Multivariate Time Series | 介绍了一种名为USAD（UnSupervised Anomaly Detection）的方法，用于对多变量时间序列进行异常检测。传统的专家监督方法已经无法满足IT系统监测的需求，因此研究人员提出了这种快速稳定的方法。该方法基于自适应训练的自动编码器，并使用对抗性训练和其架构来隔离异常情况并提供快速训练。|
| Wasm-bpf: Streamlining eBPF Deployment in Cloud Environments with WebAssembly | “Universal BPF（WASM-BPF）”的新方法，用于在云环境中简化eBPF程序的部署。传统的部署方法如独立容器或紧密集成的核心应用程序都存在不足之处，而WASM-BPF通过将eBPF程序打包为WebAssembly模块并整合到容器工具链中，实现了跨平台兼容性和动态插件管理。| 
| XRP: In-Kernel Storage Functions with eBPF | 介绍了一种名为XRP的框架，它允许应用程序在NVMe驱动程序中的eBPF钩子中执行用户定义的存储函数，从而绕过Linux内核存储堆栈的大部分开销。通过将一小部分内核状态传播到其NVMe驱动程序钩子中，XRP保留了文件系统语义，并且能够显著提高吞吐量和延迟| 
| Understanding,detecting and Localizing Partial Failures in Large System Software | 提出OmegaGen，这是一种静态分析工具，通过使用新颖的程序简化技术自动为给定程序生成定制的看门狗。已成功应用于六个大型分布式系统 |
| X-ray: Automating Root-Cause Diagnosis of Performance Anomalies in Production
Software | 它首先将性能成本归因于每个基本块。然后，它使用动态信息流跟踪来估计由于每个潜在根本原因而执行块的可能性。最后，它通过将每个区块的成本乘以所有基本区块的特定原因可能性相加来总结每个潜在根本原因的总体成本。还可以区别地执行绩效总结，以解释两项类似活动之间的绩效差异。|
| Detecting failures in distributed systems with the FALCON spy network | 网络分层故障定位 |
| Capturing and Enhancing In Situ System Observability for Failure Detection | 这是一个旨在通过利用系统组件之间的交互来增强系统的可观察性的系统。通过提供系统性渠道和分析工具，Panorama将组件转变为逻辑观察者，这样它不仅可以处理错误，还可以报告错误。 | 
|Autotuning Configurations in Distributed Systems for Performance Improvements Using Evolutionary Strategies | 比较CMA算法的另一个现有的技术称为智能爬山（SHC），并证明CMA算法在合成数据和在一个真实的系统上优于SHC算法 |
| Performance Improvement of Distributed Systems by Autotuning of the Configuration Parameters |  介绍了一种基于有序优化的策略，并结合反向传播神经网络来自动调整配置参数。该策略首次在自动化领域提出，用于复杂制造系统优化，并在这里进行了定制，以提高分布式系统性能。将该方法与协方差矩阵算法进行了比较。使用具有三层服务器的真实分布式系统进行的测试表明，该策略以合理的性能成本平均减少了40%的测试时间| 



---


笔记列表如下：
| 名称 | 说明 | 
| ---- | ----- |
| [ebpf note](./notes/ebpf_note.md) |  ebpf技术实现笔记      |  
| [NFS故障案例by秘塔](./notes/NFS故障案例by秘塔.md) | NFS文件系统的故障案例分析 |
| [故障诊断](./notes/故障诊断.md) | 故障诊断相关的笔记 |

相关博客记录如下：
| 链接 | 说明 |
| ---- | ----- |
| https://blog.ayaka.space/2024/01/Notes-CSE-dfs/ | 分布式文件系统设计，以NFS和GFS为例 | 

---

文档目录如下：
```
.
├── README.md
├── books
│   ├── 12-Linux性能优化实战 (it-ebooks) (Z-Library).epub
│   ├── 书籍百度云链接.txt          //《BPF之巅 洞悉Linux系统和应用性能，深入理解LINUX网络技术内幕，深入剖析Kubernetes 
│   ├── Kubernetes in Action中文版（博文视点图书） (七牛容器云团队) (Z-Library).pdf
│   ├── Learning eBPF Programming the Linux Kernel for Enhanced Observability, Networking, and Security (Liz Rice) (Z-Library).pdf
│   ├── Linux性能优化大师 (赵永刚) (Z-Library).epub
│   ├── Linux程序设计(第4版) (图灵程序设计丛书·LinuxUNIX系列) (马修(Neil Matthew) [马修(Neil Matthew)]) (Z-Library).pdf
│   ├── UNIX环境高级编程(第3版) ( etc.) (Z-Library).epub
│   ├── Wireshark网络分析的艺术（异步图书） (信息安全技术丛书) (林沛满 [林沛满]) (Z-Library).epub
│   ├── 循序渐进Linux（第2版） 基础知识 服务器搭建 系统管理 性能调优 虚拟化与集群应用（异步图书） (高俊峰) (Z-Library).epub
│   ├── 性能之巅：洞悉系统、企业与云计算 (布兰登格雷格) (Z-Library).pdf
│   ├── 文件系统技术内幕.pdf
├── ebpf
│   ├── Automatic Kernel Offload Using BPF.pdf
│   ├── Wasm-bpf.pdf
│   └── XRP.pdf
├── notes
│   ├── Linux全栈监控工具.png
│   ├── NFS故障案例by秘塔.md
│   ├── ebpf_note.md
│   ├── faultincluster.png
│   └── 故障诊断.md
├── 其他
│   ├── Computing_load_aware_and_long-view_load_balancing_for_cluster_storage_systems.pdf
│   └── NVM_FileSystem.pdf
├── 性能监控
│   ├── CHEOPS24-TrackIOps.pdf
│   ├── Deepflow.pdf
│   ├── EZIOtracer.pdf
│   ├── Unsupervised_Detection_of_Microservice_Trace_Anomalies_through_Service-Level_Deep_Bayesian_Networks.pdf
│   ├── nahida分布式跟踪技术.pdf
│   ├── 性能指标异常监测.pdf
│   └── 神经网络容器检测算法.pdf
├── 故障诊断
│   ├── AI训练服务的故障诊断aegis.pdf
│   ├── ART AUnified Unsupervised Framework for Incident.pdf
│   ├── Failure Diagnosis in Microservice Systems A Comprehensive Survey.pdf
│   ├── Falcon_A_Practical_Log-Based_Analysis_Tool_for_Distributed_Systems (1).pdf
│   ├── LogShrink Effective Log Compression by Leveraging.pdf
│   ├── MicroRank指标排序.pdf
│   ├── Nezha.pdf
│   ├── TrinityRCL_Multi-Granular_and_Code-Level_Root_Cause_Localization_Using_Multiple_Types_of_Telemetry_Data_in_Microservice_Systems.pdf
│   └── 缓慢故障注入.pdf
└── 配置调优
    ├── Automated Reasoning and Detection of Specious Configuration with Symbolic Execution.pdf
    ├── Capes.pdf
    ├── Carver Finding Important Parameters.pdf
    └── Towards Better Understanding of Black-box Auto-Tuning: A Comparative Analysis for Storage Systems.pdf
```