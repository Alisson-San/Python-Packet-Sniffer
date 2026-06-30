# Multiplatform Python Packet Sniffer & Ping Flood Detector

Este projeto é um sniffer de rede multiplataforma escrito em Python. Ele atua interceptando o tráfego de rede da interface hospedeira e realizando o unpacking contínuo de protocolos (Ethernet, IPv4, TCP, UDP, ICMP, HTTP). 

Como diferencial de segurança, possui um Módulo Ativo de Detecção de Ping Flood, que interpreta os cabeçalhos IPv4 e ICMP para alertar sobre anomalias e negação de serviço na rede local.

##  Tecnologias e Bibliotecas
- Python 3.x
- [Scapy](https://scapy.net/) (Motor de captura multiplataforma e filtros BPF)
- Estrutura base inspirada no repositório didático de buckyroberts.

## Instalação
1. Clone este repositório:
   `git clone https://github.com/Jfinatto/Python-Packet-Sniffer-com-detector-de-ping-flood.git`
2. Instale as dependências necessárias:
   `pip install scapy`
   *(Nota para usuários Windows: Certifique-se de possuir o driver Npcap instalado, comumente incluído com o Wireshark).*

##  Como Executar
O sniffer precisa de acesso direto à interface de rede, logo, deve ser executado com privilégios de administrador.

**No Windows (Abra o CMD como Administrador):**
```bash
python main.py

**no linux/MacOS:**
sudo python3 main.py


🇺🇸 English Version
This project is a Multiplatform Network Packet Sniffer written in Python. It intercepts network traffic from the host interface and performs continuous, real-time unpacking of multiple protocols across the link, network, and transport layers (Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, and HTTP).

As a security highlight, the system includes an Active Ping Flood Detection Module, which dynamically interprets network headers to issue real-time alerts regarding anomalies and potential Denial of Service (DoS) attacks on the local network.

🌟 Key Features
Multiplatform Capture: Powered by the Scapy library, ensuring native compatibility across Windows, Linux, and macOS.

IPv4 and IPv6 Support: Full decoding of IPv4 packets and support for dynamic traversal of IPv6 Extension Headers in accordance with IANA specifications.

Ping Flood Detection (Time Window): An algorithm based on time-bounded queues that detects rapid bursts of echo requests (Pings) originating from the same IP address within a configurable time window.

Intelligent Memory Management: An internal Garbage Collection mechanism that automatically expires and clears inactive IP history to prevent RAM overflow during long-term captures.

Structured Log Export (JSONL): Security alerts are automatically appended to a JSON Lines file (security_alerts.jsonl), allowing seamless ingestion into data pipelines, SIEMs, and analytical dashboards.

PCAP Capture Saving: Intercepted traffic is natively written into a standard PCAP file format for subsequent analysis in tools like Wireshark.

🗂️ Project File Structure
sniffer.py / main.py: The main entry point script that initializes the sniffer, processes captured packets, manages memory cleanups, and triggers anomaly checks.

ipv6.py: A specialized module for decoding the IPv6 header and implementing the dynamic header traversal algorithm to locate the actual transport protocol past any extension headers.

general.py: Utility functions for visual data formatting, multi-line hex/string representation, and parsing raw bytes into readable MAC addresses.

🛠️ Technologies and Libraries
Python 3.x

Scapy (Packet capture engine and BPF filter support)
