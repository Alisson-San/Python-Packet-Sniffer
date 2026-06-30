# ==============================================================================
# PROJETO MODIFICADO: Packet Sniffer com Detecção Avançada
# - Captura via Scapy (Multiplataforma)
# - Suporte a IPv4 e IPv6
# - Detecção de Ping Flood baseada em Janela de Tempo
# - Gerenciamento de Memória (Garbage Collection)
# - Exportação Estruturada de Logs (JSONL)
# ==============================================================================
# ==============================================================================
# MODIFIED PROJECT: Packet Sniffer with Advanced Detection
# - Capture via Scapy (Multiplatform)
# - IPv4 and IPv6 Support
# - Time-Window based Ping Flood Detection
# - Memory Management (Garbage Collection)
# - Structured Log Export (JSONL)
# =============================================================================




import sys
import platform
import argparse
import time
import json
from scapy.all import get_if_list, sniff, raw
from collections import defaultdict, deque
from general import format_multi_line
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.ipv6 import IPv6  # Certifique-se de ter criado este arquivo
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap
from networking.http import HTTP

# --- FORMATAÇÃO DE SAÍDA ---
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '

# --- VARIÁVEIS GLOBAIS DO MÓDULO DE SEGURANÇA ---
# Ping Flood Detection Settings - DEFAULT VALUES
# PING_LIMIT = 1000 ~ 1500 para detecção de Ping Flood
# TIME_WINDOW = 1 ~ 3 segundos para detecção de Ping Flood
# CLEANUP_INTERVAL = 60.0 ~ 120.0 para limpeza de memória (segundos)
# IP_TIMEOUT = 120.0 ~ 240.0 para esquecer um IP (segundos)

# --- OUTPUT FORMATTING ---

# --- SECURITY MODULE GLOBAL VARIABLES ---
# Ping Flood Detection Settings - DEFAULT VALUES
# PING_LIMIT = 1000 ~ 1500 for Ping Flood detection
# TIME_WINDOW = 1 ~ 3 seconds for Ping Flood detection
# CLEANUP_INTERVAL = 60.0 ~ 120.0 for memory cleanup (seconds)
# IP_TIMEOUT = 120.0 ~ 240.0 to forget an IP (seconds)

PING_LIMIT = 10           # Alerta disparado após 10 pings do mesmo IP (POC) ENG: Alert triggered after 10 pings from the same IP (POC)
TIME_WINDOW = 3.0         # Janela de tempo em segundos (ex: 10 pings em <= 3s) (POC) ENG: Time window in seconds (e.g., 10 pings in <= 3s) (POC)
CLEANUP_INTERVAL = 60.0   # Intervalo para rodar a limpeza de memória (segundos) ENG: Interval to run memory cleanup
IP_TIMEOUT = 120.0        # Tempo de inatividade para esquecer um IP (segundos) ENG: Inactivity time to forget an IP

# Fila para armazenar os timestamps de cada pacote por IP
# Queue to store the timestamps of each packet per IP
ping_history = defaultdict(lambda: deque(maxlen=PING_LIMIT))
last_cleanup = time.time()
pcap = None

def log_security_alert(ip_source, protocol, time_diff):
    """
    [PT]
    Grava o alerta em formato JSONL (JSON Lines) para fácil ingestão
    em pipelines de dados e dashboards analíticos.
    [ENG]
    Writes the alert in JSONL (JSON Lines) format for easy ingestion
    in data pipelines and analytical dashboards.
    """
    alert_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_type": "ping_flood",
        "protocol": protocol,
        "source_ip": ip_source,
        "packet_count": PING_LIMIT,
        "time_window_seconds": round(time_diff, 2)
    }
    
    try:
        with open("security_alerts.jsonl", "a") as log_file:
            log_file.write(json.dumps(alert_data) + "\n")
    except Exception as e:
        print(f"[!] Error writing structured log: {e}")

def process_packet(packet):
    global ping_history, last_cleanup, pcap
    current_time = time.time()

    # =========================================================
    # GERENCIADOR DE MEMÓRIA (GARBAGE COLLECTION)
    # Limpa IPs inativos para evitar estouro de memória RAM
    # =========================================================
    # =========================================================
    # MEMORY MANAGER (GARBAGE COLLECTION)
    # Clears inactive IPs to prevent RAM overflow
    # =========================================================
    if current_time - last_cleanup > CLEANUP_INTERVAL:
        stale_ips = []
        for ip, history in ping_history.items():
            # Se não há histórico ou o último pacote é muito antigo
            # If there is no history or the last packet is too old
            if not history or (current_time - history[-1] > IP_TIMEOUT):
                stale_ips.append(ip)
        
        for ip in stale_ips:
            del ping_history[ip]
            
        last_cleanup = current_time

    # =========================================================
    # FUNÇÃO DE VALIDAÇÃO DE ANOMALIA (TIME WINDOW)
    # ANOMALY VALIDATION FUNCTION (TIME WINDOW)
    # =========================================================

    def check_flood(ip_source, protocolo_nome):
        ping_history[ip_source].append(current_time)
        
        # Só analisa se a fila estiver cheia com os N pacotes definidos
        # Only analyzes if the queue is full with the N defined packets
        if len(ping_history[ip_source]) == PING_LIMIT:
            # Tempo entre o primeiro e o último pacote da fila
            # Time between the first and last packet in the queue
            time_diff = ping_history[ip_source][-1] - ping_history[ip_source][0]
            
            if time_diff <= TIME_WINDOW:
                print('\n' + '='*70)
                print(f'[!] CRITICAL ALERT: Ping Flood {protocolo_nome} detected!')
                print(f'[!] SOURCE: The IP {ip_source} fired {PING_LIMIT} packets is {time_diff:.2f}s.')
                print('='*70 + '\n')
                
                # Registra o evento estruturado
                # Registers the structured event
                log_security_alert(ip_source, protocolo_nome, time_diff)
                
                # Zera o histórico para não gerar logs duplicados em loop
                # Clears the history to avoid generating duplicate logs in a loop
                ping_history[ip_source].clear()

    # =========================================================
    # DESEMPACOTAMENTO E ANÁLISE DO TRÁFEGO
    # TRAFFIC UNPACKING AND ANALYSIS
    # =========================================================
    try:
        raw_data = raw(packet)
        if pcap:
            pcap.write(raw_data)
            
        eth = Ethernet(raw_data)

        # Imprime cabeçalho Ethernet (opcional, pode ser comentado em produção)
        # Prints Ethernet header (optional, can be commented in production)
        print('\nEthernet Frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

        # --- Camada IPv4 ---
        # --- IPv4 Layer ---[
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))
            
            # ICMPv4
            if ipv4.proto == 1:
                icmp = ICMP(ipv4.data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
                print(TAB_2 + 'ICMP Data:')
                print(format_multi_line(DATA_TAB_3, icmp.data))
                
                if icmp.type == 8:  # 8 = Echo Request
                    check_flood(ipv4.src, "IPv4")
            
            # TCP
            elif ipv4.proto == 6:
                tcp = TCP(ipv4.data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))
                
                if len(tcp.data) > 0:
                    # HTTP
                    if tcp.src_port == 80 or tcp.dest_port == 80:
                        print(TAB_2 + 'HTTP Data:')
                        try:
                            http = HTTP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_multi_line(DATA_TAB_3, tcp.data))
                    else:
                        print(TAB_2 + 'TCP Data:')
                        print(format_multi_line(DATA_TAB_3, tcp.data))
            
            # UDP
            elif ipv4.proto == 17:
                udp = UDP(ipv4.data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size))

        elif eth.proto == 34525: # 0x86DD
            ipv6 = IPv6(eth.data)

            # Imprime os detalhes do cabeçalho IPv6
            # Prints IPv6 header details
            print(TAB_1 + 'IPv6 Packet:')
            print(TAB_2 + 'Version: {}, Next Header: {}'.format(ipv6.version, ipv6.next_header))
            print(TAB_2 + 'Source: {}, Target: {}'.format(ipv6.src, ipv6.target))
            
            # ICMPv6
            if ipv6.next_header == 58:
                # Extrai Type e Code diretamente dos primeiros bytes do payload
                # Extracts Type and Code directly from the first bytes of the payload
                icmpv6_type = ipv6.data[0]
                icmpv6_code = ipv6.data[1]
                
                if icmpv6_type == 128:  # 128 = Echo Request no IPv6
                    print(TAB_1 + 'ICMPv6 Packet (Echo Request):')
                    print(TAB_2 + 'Type: {}, Code: {}'.format(icmpv6_type, icmpv6_code))
                    print(TAB_2 + 'ICMPv6 Data:')
                    
                    # Pula os 4 primeiros bytes (Type, Code, Checksum) para imprimir o payload real
                    # Skips the first 4 bytes (Type, Code, Checksum) to print the real payload
                    print(format_multi_line(DATA_TAB_3, ipv6.data[4:]))
                    
                    check_flood(ipv6.src, "IPv6")
                
                elif icmpv6_type == 129: # 129 = Echo Reply no IPv6
                    print(TAB_1 + 'ICMPv6 Packet (Echo Reply):')
                    print(TAB_2 + 'Type: {}, Code: {}'.format(icmpv6_type, icmpv6_code))
                
                else:
                    print(TAB_1 + 'ICMPv6 Packet (Outros):')
                    print(TAB_2 + 'Type: {}, Code: {}'.format(icmpv6_type, icmpv6_code))

    except Exception as e:
        # Silencia erros de pacotes malformados para não parar o sniffer
        # Silences malformed packet errors to avoid stopping the sniffer
        pass

def main():
    global pcap
    
    parser = argparse.ArgumentParser(description="Advanced Packet Sniffer.")
    parser.add_argument('-i', '--interface', type=str, default=None, help="Network interface for capture.")
    parser.add_argument('-f', '--filter', type=str, default=None, help="BPF filter for capture (e.g., 'icmp').")
    
    args = parser.parse_args()
    
    interface = args.interface
    bpf_filter = args.filter

    pcap = Pcap('capture.pcap')
    
    print("="*70)
    print(f"Sniffer Started via Scapy ({platform.system()})")
    print(f"Module: Ping Flood Detection (Time Window Active)")
    print(f"Memory Management: ON | Structured Logs: ON")
    print("Press Ctrl+C to terminate.")
    print("="*70 + "\n")
    
    try:
        sniff(iface=interface, filter=bpf_filter, prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[i] Capture terminated by the user.")
    except PermissionError:
        print("[ERROR] Insufficient permission! Run as Administrator/root.")
    except Exception as e:
        print(f"[ERROR] Capture failed: {e}")
    finally:
        if pcap:
            pcap.close()
            print("[i] .pcap file saved successfully.")

if __name__ == '__main__':
    main()