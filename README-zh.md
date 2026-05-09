# TraceGuard – 检测C2隐蔽通信技术（DNS隧道、快速切换DNS、DGA等）

[![许可证](https://img.shields.io/badge/许可证-MIT-蓝色.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-绿色)](https://www.python.org/)

> 🔍 **检测2025年恶意软件所使用的现代命令与控制（C2）隐蔽技术**  
> 专为安全运营中心（SOC）分析师、威胁猎人和网络防御人员设计。

**TraceGuard** 是一款开源工具，通过分析网络日志识别真实攻击中使用的高级C2技术，包括：
- **DNS隧道**（通过DNS协议进行数据外泄）
- **快速切换DNS（Fast Flux DNS）**（单层与双层切换）
- **域名生成算法（DGA）**
- **SSL/TLS C2滥用**（例如在恶意域名上部署合法的 Let’s Encrypt 证书）
- **云服务滥用**（GitHub Pages、Firebase、Azure Functions 等）

所有检测规则均映射到 **[MITRE ATT&CK® 框架](https://attack.mitre.org/)**，仅用于**防御性网络安全研究**。

> 📚 **想了解攻击者如何利用这些技术规避检测？**  
> 阅读我们的技术分析文章：  
> [黑客如何利用DNS隧道、SSL/TLS和Fast Flux抹去痕迹（2025）](https://data-encoder.com/hackers-erase-traces-with-dns-tunneling-ssl-tls-fast-flux-etc/)

--- 

## 🔧 功能特点

- 支持解析 **Zeek (Bro) 的 `dns.log` 和 `ssl.log`** 日志文件
- 可检测5种以上隐蔽通信技术，阈值可自定义
- 输出标准化 **JSON告警**，便于SIEM系统集成
- **完全离线运行**，无需联网，保障隐私与安全
- 开源项目，采用 **MIT 许可证**

---

## 🚀 快速开始

```bash
git clone https://gitee.com/yourname/traceguard.git
cd traceguard
pip install -r requirements.txt
python traceguard.py config.yaml
