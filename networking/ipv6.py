import socket

class IPv6:
    def __init__(self, raw_data):
        # O cabeçalho base do IPv6 possui 40 bytes.
        # The base IPv6 header has 40 bytes.
        self.version = raw_data[0] >> 4
        self.next_header = raw_data[6]
        self.src = socket.inet_ntop(socket.AF_INET6, raw_data[8:24])
        self.target = socket.inet_ntop(socket.AF_INET6, raw_data[24:40])
        
        # O payload começa imediatamente após o cabeçalho base (byte 40)
        # The payload starts immediately after the base header (byte 40
        offset = 40
        current_header = self.next_header
        
        # Códigos oficiais da IANA para Extension Headers comuns no IPv6
        # Official IANA codes for common IPv6 Extension Headers
        # 0: Hop-by-Hop, 43: Routing, 44: Fragment, 50: ESP, 51: AH, 60: Dest Options
        extension_headers = {0, 43, 44, 50, 51, 60}
        
        # Algoritmo de Travessia Dinâmica de Cabeçalhos de Extensão
        # Dynamic Extension Header Traversal Algorithm
        while current_header in extension_headers and offset < len(raw_data):
            # O primeiro byte da extensão sempre indica qual é o próximo cabeçalho da cadeia
            # The first byte of the extension always indicates what the next header in the chain is
            next_hdr = raw_data[offset]
            
            # O Fragment Header (44) é uma exceção e tem tamanho estrito de 8 bytes
            # The Fragment Header (44) is an exception and has a strict length of 8 bytes
            if current_header == 44:
                ext_len = 8
            else:
                # Para as outras extensões, o segundo byte indica o comprimento.
                # For other extensions, the second byte indicates the length.
                # A fórmula do protocolo é: (Comprimento + 1) * 8 bytes
                # The protocol formula is: (Length + 1) * 8 bytes
                hdr_ext_len = raw_data[offset + 1]
                ext_len = (hdr_ext_len + 1) * 8
                
            # Salta o bloco de memória correspondente ao cabeçalho lido
            # Skips the memory block corresponding to the read header
            offset += ext_len
            current_header = next_hdr
            
        # Após a travessia do while, current_header conterá o protocolo de transporte real (ex: 58 para ICMPv6)
        # After traversing the while loop, current_header will contain the actual transport protocol (e.g., 58 for ICMPv6)
        self.next_header = current_header
        # Isola os dados reais após descartar todo o encadeamento de rede
        # Isolates the real data after discarding all network chaining
        self.data = raw_data[offset:]