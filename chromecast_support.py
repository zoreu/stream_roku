
# -*- coding: utf-8 -*-
"""
Módulo autocontido para descoberta e controle de Chromecasts.
Não requer dependências externas. Baseado em engenharia reversa do protocolo.
"""

import socket
import struct
import json
import threading
import time
import ssl
import random
from collections import namedtuple

# ---- mDNS/Zeroconf (Descoberta) ----

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353
SERVICE_NAME = b"_googlecast._tcp.local"

# Estruturas para parsear respostas DNS
DnsHeader = struct.Struct("!HHHHHH")
DnsQuestion = namedtuple("DnsQuestion", ["name", "type", "class_"])
DnsRecord = namedtuple("DnsRecord", ["name", "type", "class_", "ttl", "data"])

def parse_dns_name(data, offset):
    parts = []
    while True:
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if (length & 0xC0) == 0xC0:  # Pointer
            pointer = struct.unpack("!H", data[offset-1:offset+1])[0] & 0x3FFF
            parts.extend(parse_dns_name(data, pointer)[0])
            offset += 1
            return parts, offset
        parts.append(data[offset:offset+length])
        offset += length
    return parts, offset

def parse_dns_packet(data):
    header = DnsHeader.unpack_from(data, 0)
    offset = DnsHeader.size
    
    questions = []
    for _ in range(header[2]):
        name_parts, offset = parse_dns_name(data, offset)
        name = b".".join(name_parts)
        type, class_ = struct.unpack_from("!HH", data, offset)
        offset += 4
        questions.append(DnsQuestion(name, type, class_))

    records = []
    for _ in range(header[3]): # Answers
        name_parts, offset = parse_dns_name(data, offset)
        name = b".".join(name_parts)
        type, class_, ttl, data_len = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        record_data = data[offset:offset+data_len]
        offset += data_len
        records.append(DnsRecord(name, type, class_, ttl, record_data))

    return questions, records

def discover_chromecasts(timeout=3):
    """Descobre Chromecasts na rede."""
    query_packet = (
        b"\x00\x00"  # ID
        b"\x01\x00"  # Flags (Standard Query)
        b"\x00\x01"  # Questions
        b"\x00\x00"  # Answers
        b"\x00\x00"  # Authority
        b"\x00\x00"  # Additional
    )
    
    parts = SERVICE_NAME.split(b".")
    for part in parts:
        query_packet += struct.pack("B", len(part)) + part
    query_packet += b"\x00"  # End of name
    query_packet += struct.pack("!HH", 12, 1)  # PTR record, IN class

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(query_packet, (MDNS_ADDR, MDNS_PORT))

    devices = {}
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            data, addr = sock.recvfrom(2048)
            _, records = parse_dns_packet(data)
            
            parsed_info = {}
            for rec in records:
                try:
                    if rec.type == 33: # SRV record
                        parsed_info['port'] = struct.unpack("!H", rec.data[4:6])[0]
                        host_parts, _ = parse_dns_name(rec.data, 6)
                        parsed_info['host'] = b".".join(host_parts).decode('utf-8')
                    elif rec.type == 1: # A record
                        parsed_info['ip'] = socket.inet_ntoa(rec.data)
                    elif rec.type == 16: # TXT record
                        txt_data = {}
                        ptr = 0
                        while ptr < len(rec.data):
                            length = rec.data[ptr]
                            ptr += 1
                            item = rec.data[ptr:ptr+length].decode('utf-8')
                            if "=" in item:
                                key, value = item.split("=", 1)
                                txt_data[key] = value
                            ptr += length
                        parsed_info['name'] = txt_data.get('fn', 'Chromecast') # Friendly Name
                except Exception:
                    continue

            if 'ip' in parsed_info and 'port' in parsed_info and 'name' in parsed_info:
                if parsed_info['ip'] not in [d['ip'] for d in devices.values()]:
                    devices[parsed_info['ip']] = {
                        "name": parsed_info['name'],
                        "ip": parsed_info['ip'],
                        "port": parsed_info['port'],
                        "tv_type": "chromecast" # Identificador
                    }
        except socket.timeout:
            break
        except Exception:
            continue
    
    sock.close()
    return list(devices.values())


# ---- Chromecast Controller ----

class ChromecastController:
    """Controlador para um dispositivo Chromecast."""

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.receiver_id = None
        self.transport_id = None
        self.request_id = random.randint(1, 1000)
        self.media_session_id = None
        self._connect()

    def _connect(self):
        """Conecta-se ao Chromecast via SSL."""
        try:
            plain_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            plain_sock.settimeout(10)
            plain_sock.connect((self.host, self.port))
            
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.sock = context.wrap_socket(plain_sock)

            self.source_id = "sender-" + str(random.randint(1000, 9999))
            self.destination_id = "receiver-0"
            
            # Conectar ao receiver
            self._send_message("urn:x-cast:com.google.cast.tp.connection", {"type": "CONNECT"})
            self._send_message("urn:x-cast:com.google.cast.receiver", {"type": "GET_STATUS"})

            # Iniciar thread para ouvir mensagens (como heartbeats e status)
            threading.Thread(target=self._listen, daemon=True).start()
            
            # Iniciar heartbeat
            threading.Thread(target=self._heartbeat_loop, daemon=True).start()

        except Exception as e:
            raise ConnectionError(f"Falha ao conectar ao Chromecast: {e}")

    def _send_message(self, namespace, payload, destination_id=None):
        """Envia uma mensagem formatada para o Chromecast."""
        if not self.sock:
            raise ConnectionError("Socket não está conectado.")
        
        if destination_id is None:
            destination_id = self.destination_id

        payload["requestId"] = self.request_id
        self.request_id += 1
        
        msg_str = json.dumps({
            "protocolVersion": 0,
            "sourceId": self.source_id,
            "destinationId": destination_id,
            "namespace": namespace,
            "payloadType": 0, # STRING
            "payloadUtf8": json.dumps(payload)
        }, separators=(',', ':'))

        # Envia a mensagem com o tamanho como prefixo (big-endian 32-bit)
        try:
            self.sock.sendall(struct.pack(">I", len(msg_str)) + msg_str.encode('utf-8'))
        except ssl.SSLError as e:
            raise ConnectionError(f"Erro de SSL ao enviar: {e}")

    def _listen(self):
        """Ouve respostas do Chromecast."""
        while self.sock:
            try:
                # Ler o tamanho da mensagem
                header_data = self.sock.recv(4)
                if not header_data: break
                msg_len = struct.unpack(">I", header_data)[0]

                # Ler a mensagem completa
                msg_data = b""
                while len(msg_data) < msg_len:
                    chunk = self.sock.recv(msg_len - len(msg_data))
                    if not chunk: break
                    msg_data += chunk
                
                msg = json.loads(msg_data.decode('utf-8'))
                payload_str = msg.get("payloadUtf8", "{}")
                payload = json.loads(payload_str)
                
                # Tratar a mensagem
                self._handle_message(msg['namespace'], payload)

            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                break
            except Exception:
                continue

    def _handle_message(self, namespace, payload):
        """Processa as mensagens recebidas."""
        msg_type = payload.get("type")
        
        if namespace == "urn:x-cast:com.google.cast.receiver" and msg_type == "RECEIVER_STATUS":
            apps = payload.get("status", {}).get("applications", [])
            if apps:
                self.receiver_id = apps[0].get("sessionId")
                self.transport_id = apps[0].get("transportId")
        
        elif namespace == "urn:x-cast:com.google.cast.media" and msg_type == "MEDIA_STATUS":
            status_list = payload.get("status", [])
            if status_list:
                self.media_session_id = status_list[0].get("mediaSessionId")

    def _heartbeat_loop(self):
        """Mantém a conexão viva enviando pings."""
        while self.sock:
            try:
                self._send_message("urn:x-cast:com.google.cast.tp.heartbeat", {"type": "PING"})
                time.sleep(5)
            except Exception:
                break

    def launch_app(self, app_id="CC1AD845"): # Default Media Receiver
        """Inicia um aplicativo (o receptor de mídia padrão)."""
        self._send_message("urn:x-cast:com.google.cast.receiver", {"type": "LAUNCH", "appId": app_id})
        
        # Espera um pouco para a app iniciar e obtermos os IDs
        for _ in range(10):
            if self.receiver_id and self.transport_id:
                # Conecta ao transport da app
                self._send_message("urn:x-cast:com.google.cast.tp.connection", {"type": "CONNECT"}, destination_id=self.transport_id)
                return True
            time.sleep(0.5)
        return False

    def load_media(self, url, content_type="application/vnd.apple.mpegurl", title="OnePlay Stream"):
        """Carrega e inicia a mídia."""
        if not self.transport_id:
            raise ConnectionError("Não foi possível obter o transportId do app.")

        media_payload = {
            "type": "LOAD",
            "media": {
                "contentId": url,
                "contentType": content_type,
                "streamType": "LIVE", # ou "BUFFERED" para VoD
                "metadata": {
                    "metadataType": 0,
                    "title": title,
                }
            },
            "autoplay": True,
        }
        self._send_message("urn:x-cast:com.google.cast.media", media_payload, destination_id=self.transport_id)

    def _control_playback(self, command_type):
        if not self.media_session_id:
            return
        payload = {"type": command_type, "mediaSessionId": self.media_session_id}
        self._send_message("urn:x-cast:com.google.cast.media", payload, destination_id=self.transport_id)

    def play(self):
        self._control_playback("PLAY")

    def pause(self):
        self._control_playback("PAUSE")

    def stop(self):
        self._control_playback("STOP")

    def disconnect(self):
        """Encerra a conexão e a sessão."""
        try:
            if self.sock:
                self._send_message("urn:x-cast:com.google.cast.tp.connection", {"type": "CLOSE"})
                self.sock.close()
        except Exception:
            pass
        finally:
            self.sock = None

# Exemplo de uso (para teste)
# if __name__ == "__main__":
#     print("Buscando Chromecasts por 5 segundos...")
#     casts = discover_chromecasts(5)
    
#     if not casts:
#         print("Nenhum Chromecast encontrado.")
#     else:
#         print(f"Encontrados {len(casts)} dispositivos:")
#         for i, cast in enumerate(casts):
#             print(f"  {i+1}: {cast['name']} ({cast['ip']}:{cast['port']})")

#         # Exemplo de como conectar e tocar algo (requer interação do usuário)
#         # choice = int(input("Escolha um dispositivo para testar: ")) - 1
#         # if 0 <= choice < len(casts):
#         #     selected_cast = casts[choice]
#         #     print(f"Conectando a {selected_cast['name']}...")
#         #     try:
#         #         cc = ChromecastController(selected_cast['ip'], selected_cast['port'])
#         #         if cc.launch_app():
#         #             print("App de mídia iniciado. Carregando stream de teste...")
#         #             # URL de um stream HLS de teste
#         #             test_url = "https://cph-p2p-msl.akamaized.net/hls/live/2000341/test/master.m3u8"
#         #             cc.load_media(test_url, title="Stream de Teste")
#         #             print("Comando para carregar mídia enviado.")
#         #             time.sleep(15) # Espera 15 segundos
#         #             cc.stop()
#         #             print("Comando de parada enviado.")
#         #         else:
#         #             print("Não foi possível iniciar o app de mídia.")
#         #         cc.disconnect()
#         #         print("Desconectado.")
#         #     except Exception as e:
#         #         print(f"Ocorreu um erro: {e}")
