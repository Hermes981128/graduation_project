# 毕业论文相关资料

## 论文题目：典型SSL加密流量识别系统设计与实现



**Github相关实现**

[MitchellX/network-traffic-analysis: 基于流量数据的网络应用识别系统设计与实现 (github.com)](https://github.com/MitchellX/network-traffic-analysis)

[KongoHuster/FlowIdentification: 在线流量识别系统 (github.com)](https://github.com/KongoHuster/FlowIdentification)

[pythonran/Pcap_tools: 网络流量可配置嗅探，流量包解析，漏洞规则扫描，生成报告. ....搞网络安全这块，还凑合着用吧 (github.com)](https://github.com/pythonran/Pcap_tools)

[HatBoy/Pcap-Analyzer: Python编写的可视化的离线数据包分析器 (github.com)](https://github.com/HatBoy/Pcap-Analyzer)	



**参考文档**

[ python3使用winpcap_凌波微分的博客-CSDN博客_python winpcap](https://blog.csdn.net/weixin_43673352/article/details/103729723)

[ Python: 从pcap文件中提取每个TCP session的payload_我小曾就是个弟弟的博客-CSDN博客](https://blog.csdn.net/qq_29848559/article/details/90744713)

**相关文章**

[Protocol Numbers 对照表](http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)

[ SSL协议原理详解_曹世宏的博客-CSDN博客_ssl协议](https://blog.csdn.net/qq_38265137/article/details/90112705)

[SSL协议之数据加密过程详解 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/32513816)

[【金睛云华AILab】基于AI的恶意加密流量检测识别效果专题研究 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/351298866)

[SSL/TLS协议运行机制的概述 - 阮一峰的网络日志 (ruanyifeng.com)](http://www.ruanyifeng.com/blog/2014/02/ssl_tls.html)

[网络入侵检测系统之加密流量识别 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/426346378)



**基础知识**

TCP Flags

```
U – URG
A – ACK
P – PSH
R – RST
S – SYN
F – FIN
```



### protocol

| 协议号  | 协议               | 说明                   |
| ------- | ------------------ | ---------------------- |
| 0       | HOPOPT             | IPv6逐跳选项           |
| 1       | ICMP               | Internet控制消息       |
| 2       | IGMP               | Internet组管理         |
| 3       | GGP                | 网关对网关             |
| 4       | IP                 | IP中的IP（封装）       |
| 5       | ST                 | 流                     |
| 6       | TCP                | 传输控制               |
| 7       | CBT                | CBT                    |
| 8       | EGP                | 外部网关协议           |
| 9       | IGP                | 任何专用内部网关(Cisco |
| 10      | BBN-RCC-MON        | BBNRCC监视             |
| 11      | NVP-II             | 网络语音协议           |
| 12      | PUP                | PUP                    |
| 13      | ARGUS              | ARGUS                  |
| 14      | EMCON              | EMCON                  |
| 15      | XNET               | 跨网调试器             |
| 16      | CHAOS              | Chaos                  |
| 17      | UDP                | 用户数据报             |
| 18      | MUX                | 多路复用               |
| 19      | DCN-MEAS           | DCN测量子系统          |
| 20      | HMP                | 主机监视               |
| 21      | PRM                | 数据包无线测量         |
| 22      | XNS-IDP            | XEROX                  |
| 23      | TRUNK-1            | 第1主干                |
| 24      | TRUNK-2            | 第2主干                |
| 25      | LEAF-1             | 第1叶                  |
| 26      | LEAF-2             | 第2叶                  |
| 27      | RDP                | 可靠数据协议           |
| 28      | IRTP               | Internet可靠事务       |
| 29      | ISO-TP4            | ISO传输协议第4类       |
| 30      | NETBLT             | 批量数据传输协议       |
| 31      | MFE-NSP            | MFE网络服务协议        |
| 32      | MERIT-INP          | MERIT节点间协议        |
| 33      | SEP                | 顺序交换协议           |
| 34      | 3PC                | 第三方连接协议         |
| 35      | IDPR               | 域间策略路由协议       |
| 36      | XTP                | XTP                    |
| 37      | DDP                | 数据报传送协议         |
| 38      | IDPR-CMTP          | IDPR控制消息传输协议   |
| 39      | TP++               | TP++传输协议           |
| 40      | IL                 | IL传输协议             |
| 41      | IPv6               | Ipv6                   |
| 42      | SDRP               | 源要求路由协议         |
| 43      | IPv6-Route         | IPv6的路由标头         |
| 44      | IPv6-Frag          | IPv6的片断标头         |
| 45      | IDRP               | 域间路由协议           |
| 46      | RSVP               | 保留协议               |
| 47      | GRE                | 通用路由封装           |
| 48      | MHRP               | 移动主机路由协议       |
| 49      | BNA                | BNA                    |
| 50      | ESP                | IPv6的封装安全负载     |
| 51      | AH                 | IPv6的身份验证标头     |
| 52      | I-NLSP             | 集成网络层安全性TUBA   |
| 53      | SWIPE              | 采用加密的IP           |
| 54      | NARP               | NBMA地址解析协议       |
| 55      | MOBILE             | IP移动性               |
| 56      | TLSP               | 传输层安全协议(使用    |
| 57      | SKIP               | SKIP                   |
| 58      | IPv6-ICMP          | 用于IPv6的ICMP         |
| 59      | IPv6-NoNxt         | 用于IPv6的无下一个标头 |
| 60      | IPv6-Opts          | IPv6的目标选项         |
| 61      | 任意主机内部协议   |                        |
| 62      | CFTP               | CFTP                   |
| 63      | 任意本地网络       |                        |
| 64      | SAT-EXPAK          | SATNET与后台EXPAK      |
| 65      | KRYPTOLAN          | Kryptolan              |
| 66      | RVD                | MIT远程虚拟磁盘协议    |
| 67      | IPPC               | Internet               |
| 68      | 任意分布式文件系统 |                        |
| 69      | SAT-MON            | SATNET监视             |
| 70      | VISA               | VISA协议               |
| 71      | IPCV               | Internet数据包核心工具 |
| 72      | CPNX               | 计算机协议网络管理     |
| 73      | CPHB               | 计算机协议检测信号     |
| 74      | WSN                | 王安电脑网络           |
| 75      | PVP                | 数据包视频协议         |
| 76      | BR-SAT-MON         | 后台SATNET监视         |
| 77      | SUN-ND             | SUN                    |
| 78      | WB-MON             | WIDEBAND监视           |
| 79      | WB-EXPAK           | WIDEBAND               |
| 80      | ISO-IP             | ISO                    |
| 81      | VMTP               | VMTP                   |
| 82      | SECURE-VMTP        | SECURE-VMTP            |
| 83      | VINES              | VINES                  |
| 84      | TTP                | TTP                    |
| 85      | NSFNET-IGP         | NSFNET-IGP             |
| 86      | DGP                | 异类网关协议           |
| 87      | TCF                | TCF                    |
| 88      | EIGRP              | EIGRP                  |
| 89      | OSPFIGP            | OSPFIGP                |
| 90      | Sprite-RPC         | Sprite                 |
| 91      | LARP               | 轨迹地址解析协议       |
| 92      | MTP                | 多播传输协议           |
| 93      | AX.25              | AX.25帧                |
| 94      | IPIP               | IP中的IP封装协议       |
| 95      | MICP               | 移动互联控制协议       |
| 96      | SCC-SP             | 信号通讯安全协议       |
| 97      | ETHERIP            | IP中的以太网封装       |
| 98      | ENCAP              | 封装标头               |
| 99      | 任意专用加密方案   |                        |
| 100     | GMTP               | GMTP                   |
| 101     | IFMP               | Ipsilon流量管理协议    |
| 102     | PNNI               | IP上的PNNI             |
| 103     | PIM                | 独立于协议的多播       |
| 104     | ARIS               | ARIS                   |
| 105     | SCPS               | SCPS                   |
| 106     | QNX                | QNX                    |
| 107     | A/N                | 活动网络               |
| 108     | IPComp             | IP负载压缩协议         |
| 109     | SNP                | Sitara网络协议         |
| 110     | Compaq-Peer        | Compaq对等协议         |
| 111     | IPX-in-IP          | IP中的IPX              |
| 112     | VRRP               | 虚拟路由器冗余协议     |
| 113     | PGM                | PGM可靠传输协议        |
| 114     | 任意0跳协议        |                        |
| 115     | L2TP               | 第二层隧道协议         |
| 116     | DDX                | D-II数据交换(DDX)      |
| 117     | IATP               | 交互式代理传输协议     |
| 118     | STP                | 计划传输协议           |
| 119     | SRP                | SpectraLink无线协议    |
| 120     | UTI                | UTI                    |
| 121     | SMP                | 简单邮件协议           |
| 122     | SM                 | SM                     |
| 123     | PTP                | 性能透明协议           |
| 124     | ISIS               | Over                   |
| 125     | FIRE               |                        |
| 126     | CRTP               | Combat无线传输协议     |
| 127     | CRUDP              | Combat无线用户数据报   |
| 128     | SSCOPMCE           |                        |
| 129     | IPLT               |                        |
| 130     | SPS                | 安全数据包防护         |
| 131     | PIPE               | IP中的专用IP封装       |
| 132     | SCTP               | 流控制传输协议         |
| 133     | FC                 | 光纤通道               |
| 134-254 |                    | 未分配                 |
| 255     |                    | 保留                   |

**代码仓库**

[王从赟/graduation_design (gitee.com)](https://gitee.com/wang981128/graduation_design)



[备案/许可证编号为：苏ICP备2021046270号](https://beian.miit.gov.cn/#/Integrated/index)

