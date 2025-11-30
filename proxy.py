# -*- coding: utf-8 -*-
"""
Proxy HTTP com DNS Customizado para QPython/Android
Python 3.6+ - Sem dependências externas
Versão LAN - Acessível de outros dispositivos na rede
"""

import json
import socket
import struct
import random
import logging
import threading
import time
import os
import re
import ssl
from urllib.parse import urljoin, urlparse, parse_qs, unquote_plus, quote
from http.client import HTTPConnection, HTTPSConnection

# ============== CONFIGURAÇÃO ==============
PORT = 8094
DEFAULT_USER_AGENT = "Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 Chrome/130.0.0.0 Mobile Safari/537.36"

# URLs das listas OnePlay
ONEPLAY_LISTS = {
    'lista01': '\x68\x74\x74\x70\x73\x3a\x2f\x2f\x6f\x6e\x65\x70\x6c\x61\x79\x68\x64\x2e\x63\x6f\x6d\x2f\x6c\x69\x73\x74\x61\x73\x5f\x6f\x6e\x65\x70\x6c\x61\x79\x2f\x6c\x69\x73\x74\x61\x30\x31\x2e\x74\x78\x74',
    'lista02': '\x68\x74\x74\x70\x73\x3a\x2f\x2f\x6f\x6e\x65\x70\x6c\x61\x79\x68\x64\x2e\x63\x6f\x6d\x2f\x6c\x69\x73\x74\x61\x73\x5f\x6f\x6e\x65\x70\x6c\x61\x79\x2f\x6c\x69\x73\x74\x61\x30\x32\x2e\x74\x78\x74',
    'lista03': '\x68\x74\x74\x70\x73\x3a\x2f\x2f\x6f\x6e\x65\x70\x6c\x61\x79\x68\x64\x2e\x63\x6f\x6d\x2f\x6c\x69\x73\x74\x61\x73\x5f\x6f\x6e\x65\x70\x6c\x61\x79\x2f\x6c\x69\x73\x74\x61\x30\x33\x2e\x74\x78\x74',
}
DEFAULT_ONEPLAY_LIST = '\x68\x74\x74\x70\x73\x3a\x2f\x2f\x6f\x6e\x65\x70\x6c\x61\x79\x68\x64\x2e\x63\x6f\x6d\x2f\x6c\x69\x73\x74\x61\x73\x5f\x6f\x6e\x65\x70\x6c\x61\x79\x2f\x6c\x69\x73\x74\x61\x30\x31\x2e\x74\x78\x74'

# ============== ESTADO GLOBAL ==============
IP_CACHE_TS = {}
IP_CACHE_MP4 = {}
AGENT_OF_CHAOS = {}
COUNT_CLEAR = {}
SHUTDOWN_EVENT = threading.Event()
LOCAL_IP = None

# ============== LOGGING ==============
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============== FUNÇÕES PARA OBTER IP LOCAL ==============
def get_local_ip():
    """Obtém o IP local da LAN"""
    methods = [
        _get_ip_by_connect,
        _get_ip_by_hostname,
        _get_ip_by_interfaces,
    ]
    
    for method in methods:
        try:
            ip = method()
            if ip and not ip.startswith('127.'):
                return ip
        except:
            continue
    
    return '127.0.0.1'


def _get_ip_by_connect():
    """Obtém IP conectando a um servidor externo (não envia dados)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        return ip
    finally:
        s.close()


def _get_ip_by_hostname():
    """Obtém IP pelo hostname"""
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    return ip


def _get_ip_by_interfaces():
    """Tenta obter IP das interfaces de rede"""
    try:
        import subprocess
        result = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=5)
        output = result.stdout
        
        patterns = [
            r'inet (192\.168\.\d+\.\d+)',
            r'inet (10\.\d+\.\d+\.\d+)',
            r'inet (172\.(?:1[6-9]|2[0-9]|3[01])\.\d+\.\d+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, output)
            if match:
                return match.group(1)
    except:
        pass
    
    return None


# ============== DNS CUSTOMIZADO ==============
class CustomDNS:
    """Resolvedor DNS customizado com cache persistente"""
    
    DNS_SERVERS = [
        '208.67.222.222',  # OpenDNS
        '208.67.220.220',  # OpenDNS
        '1.1.1.1',         # Cloudflare
        '8.8.8.8',         # Google DNS
    ]
    
    _instance = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if CustomDNS._initialized:
            return
        
        self.original_getaddrinfo = socket.getaddrinfo
        self.debug_mode = False
        
        socket.getaddrinfo = self._resolver
        CustomDNS._initialized = True
        logger.debug("CustomDNS inicializado")
    
    @staticmethod
    def is_valid_ipv4(ip):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    @staticmethod
    def is_valid_ipv6(ip):
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except (socket.error, OSError):
            return False
    
    def _build_dns_query(self, domain):
        """Constrói query DNS"""
        transaction_id = random.randint(0, 65535)
        flags = 0x0100
        questions = 1
        header = struct.pack('>HHHHHH', transaction_id, flags, questions, 0, 0, 0)
        
        qname = b''.join(
            bytes([len(part)]) + part.encode() 
            for part in domain.split('.')
        ) + b'\x00'
        
        qtype = 1
        qclass = 1
        question = qname + struct.pack('>HH', qtype, qclass)
        
        return header + question
    
    def _parse_dns_response(self, data):
        """Parse resposta DNS"""
        try:
            answer_count = struct.unpack(">H", data[6:8])[0]
            offset = 12
            
            while data[offset] != 0:
                offset += 1
            offset += 5
            
            for _ in range(answer_count):
                if data[offset] & 0xC0 == 0xC0:
                    offset += 2
                else:
                    while data[offset] != 0:
                        offset += 1
                    offset += 1
                
                rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset+10])
                offset += 10
                
                if rtype == 1 and rdlength == 4:
                    ip_parts = struct.unpack(">BBBB", data[offset:offset+4])
                    return ".".join(map(str, ip_parts))
                
                offset += rdlength
        except Exception as e:
            logger.debug(f"Erro ao parsear resposta DNS: {e}")
        
        return None
    
    def resolve(self, domain, dns_server):
        """Resolve domínio usando servidor DNS específico"""
        try:
            domain_clean = domain.strip('.')
            query = self._build_dns_query(domain_clean)
            
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.sendto(query, (dns_server, 53))
            data, _ = s.recvfrom(512)
            s.close()
            
            ip = self._parse_dns_response(data)
            if ip:
                return ip
        except Exception as e:
            if self.debug_mode:
                logger.debug(f"DNS resolve falhou para {domain} via {dns_server}: {e}")
        
        return None
    
    def _resolver(self, host, port, family=0, type=0, proto=0, flags=0):
        """Substitui socket.getaddrinfo"""
        try:
            if self.is_valid_ipv4(host):
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (host, port))]
            if self.is_valid_ipv6(host):
                return [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', (host, port, 0, 0))]
            
            for dns_server in self.DNS_SERVERS:
                ip = self.resolve(host, dns_server)
                if ip:
                    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, port))]
        except Exception as e:
            logger.debug(f"Erro no resolver DNS para {host}: {e}")
        
        return self.original_getaddrinfo(host, port, family, type, proto, flags)


# ============== HTTP CLIENT SIMPLES ==============
class SimpleHTTPClient:
    """Cliente HTTP simples sem dependências externas"""
    
    def __init__(self, timeout=15):
        self.timeout = timeout
    
    def request(self, url, headers=None, stream=False, allow_redirects=True, max_redirects=5):
        """Faz requisição HTTP/HTTPS"""
        if headers is None:
            headers = {}
        
        redirect_count = 0
        current_url = url
        
        while redirect_count <= max_redirects:
            parsed = urlparse(current_url)
            host = parsed.netloc
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query
            
            is_https = parsed.scheme == 'https'
            port = 443 if is_https else 80
            
            if ':' in host:
                host, port_str = host.rsplit(':', 1)
                port = int(port_str)
            
            try:
                if is_https:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    conn = HTTPSConnection(host, port, timeout=self.timeout, context=context)
                else:
                    conn = HTTPConnection(host, port, timeout=self.timeout)
                
                request_headers = {
                    'Host': parsed.netloc,
                    'User-Agent': DEFAULT_USER_AGENT,
                    'Accept': '*/*',
                    'Connection': 'keep-alive',
                }
                request_headers.update(headers)
                
                conn.request('GET', path, headers=request_headers)
                response = conn.getresponse()
                
                if allow_redirects and response.status in (301, 302, 303, 307, 308):
                    location = response.getheader('Location')
                    if location:
                        if not location.startswith('http'):
                            location = urljoin(current_url, location)
                        current_url = location
                        redirect_count += 1
                        response.close()
                        conn.close()
                        continue
                
                return HTTPResponse(response, conn, current_url)
                
            except Exception as e:
                logger.debug(f"Erro HTTP para {current_url}: {e}")
                raise
        
        raise Exception(f"Muitos redirects para {url}")


class HTTPResponse:
    """Wrapper para resposta HTTP"""
    
    def __init__(self, response, connection, final_url):
        self._response = response
        self._connection = connection
        self.status_code = response.status
        self.headers = dict(response.getheaders())
        self.url = final_url
        self._content = None
    
    @property
    def content(self):
        if self._content is None:
            self._content = self._response.read()
        return self._content
    
    def iter_content(self, chunk_size=4096):
        """Itera sobre o conteúdo em chunks"""
        while True:
            chunk = self._response.read(chunk_size)
            if not chunk:
                break
            yield chunk
    
    def close(self):
        try:
            self._response.close()
            self._connection.close()
        except:
            pass


# ============== FUNÇÕES UTILITÁRIAS ==============
def get_ip(headers, client_address):
    """Extrai IP do cliente"""
    forwarded_for = headers.get("X-Forwarded-For", "")
    real_ip = headers.get("X-Real-IP", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    elif real_ip:
        return real_ip
    return client_address[0]


def get_cache_key(client_ip, url):
    """Gera chave de cache"""
    return f"{client_ip}:{url}"


def random_hex(length=32):
    """Gera string hexadecimal aleatória"""
    return ''.join(random.choice('0123456789abcdef') for _ in range(length))


def rewrite_m3u8_urls(playlist_content, base_url, scheme, host):
    """Reescreve URLs no playlist m3u8 para passar pelo proxy"""
    
    def replace_url(match):
        segment_url = match.group(0).strip()
        if segment_url.startswith('#') or not segment_url or segment_url == '/':
            return segment_url
        try:
            absolute_url = urljoin(base_url + '/', segment_url)
            if not any(x in absolute_url.lower() for x in ['.ts', '/hl', '.m3u8']):
                return segment_url
            proxied_url = f"{scheme}://{host}/hlsretry?url={quote(absolute_url)}"
            return proxied_url
        except Exception as e:
            logger.debug(f"Erro ao reescrever URL {segment_url}: {e}")
            return segment_url
    
    return re.sub(r'^(?!#)\S+', replace_url, playlist_content, flags=re.MULTILINE)


def rewrite_m3u_playlist(playlist_content, proxy_host):
    """
    Reescreve URLs em uma lista M3U/M3U8 para passar pelo proxy.
    Suporta URLs de stream (.m3u8, .ts, etc.)
    """
    lines = playlist_content.split('\n')
    rewritten_lines = []
    
    for line in lines:
        line = line.strip()
        
        # Manter linhas vazias
        if not line:
            rewritten_lines.append(line)
            continue
        
        # Manter linhas de metadados (começam com #)
        if line.startswith('#'):
            rewritten_lines.append(line)
            continue
        
        # Processar URLs
        if line.startswith('http://') or line.startswith('https://'):
            # Adicionar proxy na frente da URL
            proxied_url = f"http://{proxy_host}/hlsretry?url={quote(line)}"
            rewritten_lines.append(proxied_url)
        else:
            # Manter outras linhas como estão
            rewritten_lines.append(line)
    
    return '\n'.join(rewritten_lines)


def fetch_oneplay_list(list_url, proxy_host):
    """
    Baixa a lista OnePlay e reescreve as URLs com o proxy.
    """
    http_client = SimpleHTTPClient(timeout=15)
    
    try:
        logger.info(f"Baixando lista: {list_url}")
        response = http_client.request(list_url)
        
        if response.status_code == 200:
            content = response.content.decode('utf-8', errors='ignore')
            response.close()
            
            # Reescrever URLs com proxy
            rewritten = rewrite_m3u_playlist(content, proxy_host)
            
            logger.info(f"Lista baixada e processada com sucesso")
            return rewritten
        else:
            response.close()
            logger.error(f"Erro ao baixar lista: HTTP {response.status_code}")
            return None
            
    except Exception as e:
        logger.error(f"Erro ao baixar lista OnePlay: {e}")
        return None


def stream_response(response, client_ip, url):
    """Stream de resposta com cache"""
    cache_key = get_cache_key(client_ip, url) if any(ext in url.lower() for ext in ['.mp4', '.m3u8']) else client_ip
    is_ts = '.ts' in url.lower() or '/hl' in url.lower()
    
    bytes_read = 0
    try:
        for chunk in response.iter_content(chunk_size=4096):
            if chunk:
                bytes_read += len(chunk)
                
                if '.mp4' in url.lower():
                    if cache_key not in IP_CACHE_MP4:
                        IP_CACHE_MP4[cache_key] = []
                    IP_CACHE_MP4[cache_key].append(chunk)
                    if len(IP_CACHE_MP4[cache_key]) > 20:
                        IP_CACHE_MP4[cache_key].pop(0)
                
                elif is_ts:
                    if cache_key not in IP_CACHE_TS:
                        IP_CACHE_TS[cache_key] = []
                    IP_CACHE_TS[cache_key].append(chunk)
                    if len(IP_CACHE_TS[cache_key]) > 20:
                        IP_CACHE_TS[cache_key].pop(0)
                
                yield chunk
    except Exception as e:
        logger.debug(f"Erro no stream (bytes lidos: {bytes_read}): {e}")
        cache = IP_CACHE_TS if is_ts else IP_CACHE_MP4
        for chunk in cache.get(cache_key, [])[-5:]:
            yield chunk
    finally:
        try:
            response.close()
        except:
            pass


def stream_cache(client_ip, url):
    """Stream de chunks cacheados"""
    if not url:
        return None
    
    cache_key = get_cache_key(client_ip, url) if any(ext in url.lower() for ext in ['.mp4', '.m3u8']) else client_ip
    
    if '.mp4' in url.lower():
        cache = IP_CACHE_MP4
    elif '.ts' in url.lower() or '/hl' in url.lower():
        cache = IP_CACHE_TS
    else:
        return None
    
    if cache_key in cache:
        for chunk in cache.get(cache_key, [])[-5:]:
            yield chunk


def parse_http_request(data):
    """Parse requisição HTTP"""
    lines = data.split('\r\n')
    if not lines:
        return None, None, {}
    
    request_line = lines[0]
    parts = request_line.split(' ')
    if len(parts) < 3:
        return None, None, {}
    
    method = parts[0]
    path = parts[1]
    
    headers = {}
    for line in lines[1:]:
        if ': ' in line:
            key, value = line.split(': ', 1)
            headers[key] = value
        elif line == '':
            break
    
    return method, path, headers


# ============== HANDLER DE REQUISIÇÕES ==============
def handle_request(client_socket, client_address, server_socket):
    """Processa requisição HTTP"""
    global LOCAL_IP
    http_client = SimpleHTTPClient(timeout=15)
    
    try:
        client_socket.settimeout(10)
        request_data = client_socket.recv(8192).decode('utf-8', errors='ignore')
        
        if not request_data:
            return
        
        method, path, headers = parse_http_request(request_data)
        
        if not method or not path:
            return
        
        if method != 'GET':
            client_socket.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return
        
        # Parse path e query params
        if '?' in path:
            path_part, query_string = path.split('?', 1)
            query_params = parse_qs(query_string)
        else:
            path_part = path
            query_params = {}
        
        client_ip = get_ip(headers, client_address)
        
        # Host para rewrite de m3u8 (usa IP local da LAN)
        proxy_host = f"{LOCAL_IP}:{PORT}"
        
        # ===== ROTA: / =====
        if path_part == "/":
            response_data = {
                "message": "ONEPLAY PROXY - QPython LAN Edition",
                "status": "running",
                "local_ip": LOCAL_IP,
                "port": PORT,
                "endpoints": {
                    "status": f"http://{proxy_host}/",
                    "oneplay": f"http://{proxy_host}/oneplay",
                    "oneplay_lista": f"http://{proxy_host}/oneplay?lista=lista01",
                    "hlsretry": f"http://{proxy_host}/hlsretry?url=<URL>",
                    "tsdownloader": f"http://{proxy_host}/tsdownloader?url=<URL>",
                    "stop": f"http://{proxy_host}/stop"
                },
                "listas_disponiveis": list(ONEPLAY_LISTS.keys())
            }
            response = json.dumps(response_data, indent=2)
            client_socket.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
                response.encode('utf-8')
            )
        
        # ===== ROTA: /stop =====
        elif path_part == "/stop":
            response = json.dumps({"message": "Proxy shutting down"})
            client_socket.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
                response.encode('utf-8')
            )
            SHUTDOWN_EVENT.set()
            try:
                server_socket.close()
            except:
                pass
        
        # ===== ROTA: /oneplay =====
        elif path_part == "/oneplay":
            # Verificar qual lista usar
            lista_param = query_params.get('lista', [None])[0]
            
            if lista_param and lista_param in ONEPLAY_LISTS:
                list_url = ONEPLAY_LISTS[lista_param]
            else:
                list_url = DEFAULT_ONEPLAY_LIST
            
            # Baixar e processar a lista
            rewritten_playlist = fetch_oneplay_list(list_url, proxy_host)
            
            if rewritten_playlist:
                # Enviar a lista M3U com proxy
                response_headers = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Disposition: inline; filename=\"oneplay.m3u\"\r\n"
                    b"Cache-Control: no-cache\r\n"
                    b"\r\n"
                )
                client_socket.sendall(response_headers + rewritten_playlist.encode('utf-8'))
            else:
                # Erro ao baixar a lista
                error_response = json.dumps({
                    "error": "Falha ao baixar lista OnePlay",
                    "url": list_url,
                    "listas_disponiveis": list(ONEPLAY_LISTS.keys()),
                    "exemplo": f"http://{proxy_host}/oneplay?lista=lista01"
                })
                client_socket.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\n\r\n" +
                    error_response.encode('utf-8')
                )
        
        # ===== ROTA: /oneplay/listas =====
        elif path_part == "/oneplay/listas":
            # Listar todas as listas disponíveis
            response_data = {
                "listas": {}
            }
            for nome, url in ONEPLAY_LISTS.items():
                response_data["listas"][nome] = {
                    "url_original": url,
                    "url_proxy": f"http://{proxy_host}/oneplay?lista={nome}"
                }
            
            response = json.dumps(response_data, indent=2)
            client_socket.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
                response.encode('utf-8')
            )
        
        # ===== ROTA: /hlsretry =====
        elif path_part == "/hlsretry":
            url = query_params.get('url', [None])[0]
            if url:
                try:
                    url = unquote_plus(url)
                except:
                    pass
            
            if not url:
                client_socket.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\nNo URL provided")
                return
            
            cache_key = get_cache_key(client_ip, url) if any(x in url.lower() for x in ['.mp4', '.m3u8']) else client_ip
            
            req_headers = {k: v for k, v in headers.items() if k.lower() != 'host'}
            original_ua = req_headers.get('User-Agent', DEFAULT_USER_AGENT)
            
            max_retries = 7
            attempts = 0
            tried_without_range = False
            change_user_agent = False
            
            media_type = (
                'video/mp4' if '.mp4' in url.lower()
                else 'video/mp2t' if '.ts' in url.lower() or '/hl' in url.lower()
                else 'application/octet-stream'
            )
            response_headers = {}
            status = 200
            
            while attempts < max_retries:
                try:
                    if '.mp4' in url.lower() and 'Range' in req_headers and tried_without_range:
                        del req_headers['Range']
                    
                    if AGENT_OF_CHAOS.get(cache_key) and not ('.ts' in url.lower() or '/hl' in url.lower()):
                        if change_user_agent:
                            req_headers['User-Agent'] = AGENT_OF_CHAOS[cache_key]
                        else:
                            req_headers['User-Agent'] = original_ua
                    elif '.ts' in url.lower() or '/hl' in url.lower():
                        if change_user_agent or 'User-Agent' not in req_headers:
                            req_headers['User-Agent'] = random_hex(32)
                        else:
                            req_headers['User-Agent'] = original_ua
                    
                    response = http_client.request(url, headers=req_headers, stream=True)
                    
                    if response.status_code in (200, 206):
                        if '.mp4' in url.lower() or '.m3u8' in url.lower():
                            url = response.url
                        
                        change_user_agent = False
                        
                        if client_ip in COUNT_CLEAR and COUNT_CLEAR.get(client_ip, 0) > 4:
                            AGENT_OF_CHAOS.pop(cache_key, None)
                            IP_CACHE_MP4.pop(cache_key, None)
                            IP_CACHE_TS.pop(cache_key, None)
                            COUNT_CLEAR[client_ip] = 0
                        else:
                            COUNT_CLEAR[client_ip] = COUNT_CLEAR.get(client_ip, 0) + 1
                        
                        content_type = response.headers.get("Content-Type", "").lower()
                        
                        # Processar m3u8
                        if "mpegurl" in content_type or ".m3u8" in url.lower():
                            base_url = url.rsplit('/', 1)[0]
                            playlist_content = response.content.decode('utf-8', errors='ignore')
                            rewritten = rewrite_m3u8_urls(playlist_content, base_url, 'http', proxy_host)
                            client_socket.sendall(
                                b"HTTP/1.1 200 OK\r\nContent-Type: application/x-mpegURL\r\n\r\n" +
                                rewritten.encode('utf-8')
                            )
                            return
                        
                        # Ajustar URL de segmento TS
                        if '/hl' in url.lower() and '_' in url.lower() and '.ts' in url.lower():
                            try:
                                seg_ = re.findall(r'_(.*?)\.ts', url)[0]
                                url = url.replace(f'_{seg_}.ts', f'_{int(seg_) + 1}.ts')
                            except:
                                pass
                        
                        media_type = (
                            'video/mp4' if '.mp4' in url.lower()
                            else 'video/mp2t' if '.ts' in url.lower() or '/hl' in url.lower()
                            else response.headers.get("Content-Type", "application/octet-stream")
                        )
                        
                        response_headers = {
                            k: v for k, v in response.headers.items()
                            if k.lower() in ['content-type', 'accept-ranges', 'content-range']
                        }
                        status = 206 if response.status_code == 206 else 200
                        
                        header_str = f"HTTP/1.1 {status} OK\r\n"
                        for k, v in response_headers.items():
                            header_str += f"{k}: {v}\r\n"
                        header_str += f"Content-Type: {media_type}\r\n\r\n"
                        client_socket.sendall(header_str.encode('utf-8'))
                        
                        for chunk in stream_response(response, client_ip, url):
                            try:
                                client_socket.sendall(chunk)
                            except (BrokenPipeError, ConnectionResetError):
                                return
                        return
                    
                    elif response.status_code == 416 and 'Range' in req_headers and not tried_without_range:
                        tried_without_range = True
                        response.close()
                        continue
                    
                    else:
                        change_user_agent = True
                        logger.debug(f"Erro código {response.status_code}, tentativa {attempts}")
                        AGENT_OF_CHAOS[cache_key] = random_hex(32)
                        response.close()
                        time.sleep(2)
                        attempts += 1
                        
                        if any(x in url.lower() for x in ['.ts', '/hl', '.mp4']):
                            header_str = f"HTTP/1.1 {status} OK\r\nContent-Type: {media_type}\r\n"
                            for k, v in response_headers.items():
                                header_str += f"{k}: {v}\r\n"
                            header_str += "\r\n"
                            client_socket.sendall(header_str.encode('utf-8'))
                            
                            for chunk in stream_cache(client_ip, url) or []:
                                try:
                                    client_socket.sendall(chunk)
                                except:
                                    break
                            return
                
                except Exception as e:
                    change_user_agent = True
                    logger.debug(f"Erro na requisição: {e}")
                    AGENT_OF_CHAOS[cache_key] = random_hex(32)
                    time.sleep(2)
                    attempts += 1
                    
                    if any(x in url.lower() for x in ['.ts', '/hl', '.mp4']):
                        header_str = f"HTTP/1.1 {status} OK\r\nContent-Type: {media_type}\r\n\r\n"
                        client_socket.sendall(header_str.encode('utf-8'))
                        
                        for chunk in stream_cache(client_ip, url) or []:
                            try:
                                client_socket.sendall(chunk)
                            except:
                                break
                        return
            
            client_socket.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\nFailed after multiple attempts")
        
        # ===== ROTA: /tsdownloader =====
        elif path_part == "/tsdownloader":
            url = query_params.get('url', [None])[0]
            if not url:
                client_socket.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\nMissing 'url' parameter")
                return
            
            try:
                url = unquote_plus(url)
            except:
                pass
            
            req_headers = {k: v for k, v in headers.items() if k.lower() != 'host'}
            stop_ts = False
            last_url = ''
            
            client_socket.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: video/mp2t\r\n\r\n")
            
            while not stop_ts and not SHUTDOWN_EVENT.is_set():
                try:
                    if not last_url:
                        response = http_client.request(url, headers=req_headers, stream=True)
                        last_url = response.url
                        response.close()
                    
                    response = http_client.request(last_url, headers=req_headers, stream=True)
                    
                    if response.status_code == 200:
                        for chunk in response.iter_content(chunk_size=4096):
                            if stop_ts or SHUTDOWN_EVENT.is_set():
                                break
                            if chunk:
                                try:
                                    client_socket.sendall(chunk)
                                except (BrokenPipeError, ConnectionResetError):
                                    stop_ts = True
                                    break
                        response.close()
                    else:
                        logger.warning(f"[TS Downloader] HTTP {response.status_code}")
                        response.close()
                        time.sleep(1)
                
                except Exception as e:
                    logger.warning(f"[TS Downloader] Erro: {e}")
                    time.sleep(1)
        
        # ===== ROTA NÃO ENCONTRADA =====
        else:
            client_socket.sendall(b"HTTP/1.1 404 Not Found\r\n\r\nNot Found")
    
    except socket.timeout:
        pass
    except Exception as e:
        logger.debug(f"Erro ao processar requisição: {e}")
    finally:
        try:
            client_socket.close()
        except:
            pass


# ============== SERVIDOR ==============
def is_proxy_running():
    """Verifica se o proxy já está rodando"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(('127.0.0.1', PORT))
        s.close()
        return True
    except socket.error:
        return False


def print_banner(local_ip, port):
    """Exibe banner com informações do servidor"""
    print("\n" + "=" * 60)
    print("   ██████╗ ███╗   ██╗███████╗██████╗ ██╗      █████╗ ██╗   ██╗")
    print("  ██╔═══██╗████╗  ██║██╔════╝██╔══██╗██║     ██╔══██╗╚██╗ ██╔╝")
    print("  ██║   ██║██╔██╗ ██║█████╗  ██████╔╝██║     ███████║ ╚████╔╝ ")
    print("  ██║   ██║██║╚██╗██║██╔══╝  ██╔═══╝ ██║     ██╔══██║  ╚██╔╝  ")
    print("  ╚██████╔╝██║ ╚████║███████╗██║     ███████╗██║  ██║   ██║   ")
    print("   ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   ")
    print("=" * 60)
    print("              PROXY HLS - LAN Edition")
    print("=" * 60)
    print(f"\n  🌐 IP Local (LAN): {local_ip}")
    print(f"  🔌 Porta: {port}")
    print(f"\n  📡 URLs de Acesso:")
    print(f"     • http://{local_ip}:{port}/")
    print(f"     • http://127.0.0.1:{port}/")
    print(f"\n  🎬 Endpoints Disponíveis:")
    print(f"     • /oneplay                - Lista IPTV com proxy")
    print(f"     • /oneplay?lista=lista01  - Lista específica")
    print(f"     • /oneplay/listas         - Ver listas disponíveis")
    print(f"     • /hlsretry?url=<URL>     - Proxy HLS com retry")
    print(f"     • /tsdownloader?url=<URL> - Download de stream TS")
    print(f"     • /stop                   - Parar o servidor")
    print(f"\n  📺 Listas OnePlay Disponíveis:")
    for nome in ONEPLAY_LISTS.keys():
        print(f"     • {nome}: http://{local_ip}:{port}/oneplay?lista={nome}")
    print(f"\n  💡 Use no Web Video Cast, VLC ou qualquer player IPTV!")
    print(f"\n  ⌨️  Pressione Ctrl+C para parar o servidor")
    print("=" * 60 + "\n")


def start_proxy():
    """Inicia o servidor proxy"""
    global SHUTDOWN_EVENT, LOCAL_IP
    
    if is_proxy_running():
        print(f"\n❌ Proxy já está rodando na porta {PORT}")
        return False
    
    # Obter IP local
    LOCAL_IP = get_local_ip()
    
    # Inicializar DNS customizado
    CustomDNS()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        # Bind em 0.0.0.0 para aceitar conexões de qualquer IP
        server_socket.bind(('0.0.0.0', PORT))
        server_socket.listen(10)
        server_socket.settimeout(1)
    except socket.error as e:
        print(f"\n❌ Falha ao iniciar servidor na porta {PORT}: {e}")
        server_socket.close()
        return False
    
    # Exibir banner
    print_banner(LOCAL_IP, PORT)
    
    try:
        while not SHUTDOWN_EVENT.is_set():
            try:
                client_socket, client_address = server_socket.accept()
                logger.debug(f"Conexão de {client_address[0]}:{client_address[1]}")
                thread = threading.Thread(
                    target=handle_request,
                    args=(client_socket, client_address, server_socket)
                )
                thread.daemon = True
                thread.start()
            except socket.timeout:
                continue
            except socket.error as e:
                if not SHUTDOWN_EVENT.is_set():
                    logger.error(f"Erro ao aceitar conexão: {e}")
    
    except KeyboardInterrupt:
        print("\n\n" + "=" * 60)
        print("  ⏹️  Interrupção detectada (Ctrl+C)")
        print("  🛑 Encerrando servidor proxy...")
        print("=" * 60 + "\n")
    
    finally:
        SHUTDOWN_EVENT.set()
        server_socket.close()
        print("✅ Servidor proxy encerrado com sucesso!\n")
    
    return True


def stop_proxy():
    """Para o proxy enviando requisição /stop"""
    local_ip = get_local_ip()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((local_ip, PORT))
        s.sendall(b"GET /stop HTTP/1.1\r\nHost: localhost\r\n\r\n")
        response = s.recv(1024).decode('utf-8', errors='ignore')
        s.close()
        print(f"\n✅ Comando de parada enviado para {local_ip}:{PORT}")
        return True
    except Exception as e:
        print(f"\n❌ Erro ao parar proxy: {e}")
        return False


def check_status():
    """Verifica status do proxy"""
    local_ip = get_local_ip()
    
    print(f"\n🔍 Verificando status do proxy...")
    print(f"   IP Local: {local_ip}")
    print(f"   Porta: {PORT}")
    
    if is_proxy_running():
        print(f"\n✅ Proxy está RODANDO em http://{local_ip}:{PORT}/")
    else:
        print(f"\n❌ Proxy NÃO está rodando")


# ============== MAIN ==============
if __name__ == '__main__':
    start_proxy()
