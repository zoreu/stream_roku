# -*- coding: utf-8 -*-
"""
Proxy HTTP com DNS Customizado para QPython/Android
Python 3.6+ - Sem dependências externas
Versão LAN - Acessível de outros dispositivos na rede
DEBUG VERSION - Logging detalhado
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
import traceback
import sys
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
LOG_ = False

# ============== LOGGING DETALHADO ==============
# Criar logger com nível DEBUG
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(funcName)s:%(lineno)d - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Função helper para log detalhado
def log_debug(msg):
    """Log com informação de thread"""
    if LOG_:
        thread_name = threading.current_thread().name
        logger.debug(f"[{thread_name}] {msg}")

def log_info(msg):
    """Log info com thread"""
    if LOG_:
        thread_name = threading.current_thread().name
        logger.info(f"[{thread_name}] {msg}")

def log_error(msg):
    """Log error com thread"""
    if LOG_:
        thread_name = threading.current_thread().name
        logger.error(f"[{thread_name}] {msg}")

def log_exception(msg):
    """Log exception com traceback completo"""
    if LOG_:
        thread_name = threading.current_thread().name
        logger.error(f"[{thread_name}] {msg}")
        logger.error(traceback.format_exc())


# ============== FUNÇÕES PARA OBTER IP LOCAL ==============
def get_local_ip():
    """Obtém o IP local da LAN"""
    log_debug("Tentando obter IP local...")
    
    methods = [
        ('connect', _get_ip_by_connect),
        ('hostname', _get_ip_by_hostname),
        ('interfaces', _get_ip_by_interfaces),
    ]
    
    for name, method in methods:
        try:
            log_debug(f"Tentando método: {name}")
            ip = method()
            if ip and not ip.startswith('127.'):
                log_info(f"IP local obtido via {name}: {ip}")
                return ip
            else:
                log_debug(f"Método {name} retornou: {ip}")
        except Exception as e:
            log_debug(f"Método {name} falhou: {e}")
            continue
    
    log_info("Usando fallback: 127.0.0.1")
    return '127.0.0.1'


def _get_ip_by_connect():
    """Obtém IP conectando a um servidor externo (não envia dados)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(5)
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
    _cache = {}  # Cache de DNS em memória
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if CustomDNS._initialized:
            return
        
        self.original_getaddrinfo = socket.getaddrinfo
        self.debug_mode = True  # Ativar debug
        
        socket.getaddrinfo = self._resolver
        CustomDNS._initialized = True
        log_info("CustomDNS inicializado com debug ativado")
    
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
            log_debug(f"Erro ao parsear resposta DNS: {e}")
        
        return None
    
    def resolve(self, domain, dns_server):
        """Resolve domínio usando servidor DNS específico"""
        # Verificar cache primeiro
        cache_key = f"{domain}:{dns_server}"
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            if time.time() - cached['time'] < 300:  # 5 min cache
                log_debug(f"DNS cache hit: {domain} -> {cached['ip']}")
                return cached['ip']
        
        try:
            domain_clean = domain.strip('.')
            log_debug(f"Resolvendo DNS: {domain_clean} via {dns_server}")
            
            query = self._build_dns_query(domain_clean)
            
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)  # Aumentar timeout
            s.sendto(query, (dns_server, 53))
            data, _ = s.recvfrom(512)
            s.close()
            
            ip = self._parse_dns_response(data)
            if ip:
                # Salvar no cache
                self._cache[cache_key] = {'ip': ip, 'time': time.time()}
                log_debug(f"DNS resolvido: {domain_clean} -> {ip}")
                return ip
            else:
                log_debug(f"DNS sem resposta para: {domain_clean}")
        except socket.timeout:
            log_debug(f"DNS timeout para {domain} via {dns_server}")
        except Exception as e:
            log_debug(f"DNS erro para {domain} via {dns_server}: {e}")
        
        return None
    
    def _resolver(self, host, port, family=0, type=0, proto=0, flags=0):
        """Substitui socket.getaddrinfo"""
        log_debug(f"Resolver chamado para: {host}:{port}")
        
        try:
            if self.is_valid_ipv4(host):
                log_debug(f"Host já é IPv4: {host}")
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (host, port))]
            if self.is_valid_ipv6(host):
                log_debug(f"Host já é IPv6: {host}")
                return [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', (host, port, 0, 0))]
            
            for dns_server in self.DNS_SERVERS:
                ip = self.resolve(host, dns_server)
                if ip:
                    log_debug(f"Resolvido {host} -> {ip} via {dns_server}")
                    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, port))]
            
            log_debug(f"Todos DNS falharam para {host}, usando fallback")
        except Exception as e:
            log_error(f"Erro no resolver DNS para {host}: {e}")
        
        # Fallback para resolver original
        try:
            result = self.original_getaddrinfo(host, port, family, type, proto, flags)
            log_debug(f"Fallback resolver para {host}: {result}")
            return result
        except Exception as e:
            log_error(f"Fallback também falhou para {host}: {e}")
            raise


# ============== HTTP CLIENT SIMPLES ==============
class SimpleHTTPClient:
    """Cliente HTTP simples sem dependências externas"""
    
    def __init__(self, timeout=15):
        self.timeout = timeout
        log_debug(f"HTTPClient criado com timeout={timeout}")
    
    def request(self, url, headers=None, stream=False, allow_redirects=True, max_redirects=5):
        """Faz requisição HTTP/HTTPS"""
        log_info(f"=== HTTP REQUEST ===")
        log_info(f"URL: {url}")
        log_debug(f"Headers: {headers}")
        log_debug(f"allow_redirects={allow_redirects}, max_redirects={max_redirects}")
        
        if headers is None:
            headers = {}
        
        redirect_count = 0
        current_url = url
        
        while redirect_count <= max_redirects:
            try:
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
                
                log_debug(f"Conectando: host={host}, port={port}, https={is_https}")
                log_debug(f"Path: {path}")
                
                conn = None
                try:
                    if is_https:
                        log_debug("Criando conexão HTTPS...")
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        conn = HTTPSConnection(host, port, timeout=self.timeout, context=context)
                    else:
                        log_debug("Criando conexão HTTP...")
                        conn = HTTPConnection(host, port, timeout=self.timeout)
                    
                    request_headers = {
                        'Host': parsed.netloc,
                        'User-Agent': DEFAULT_USER_AGENT,
                        'Accept': '*/*',
                        'Connection': 'keep-alive',
                    }
                    request_headers.update(headers)
                    
                    log_debug(f"Request headers: {request_headers}")
                    log_debug(f"Enviando GET {path}...")
                    
                    conn.request('GET', path, headers=request_headers)
                    
                    log_debug("Aguardando resposta...")
                    response = conn.getresponse()
                    
                    log_info(f"Response status: {response.status} {response.reason}")
                    log_debug(f"Response headers: {dict(response.getheaders())}")
                    
                    if allow_redirects and response.status in (301, 302, 303, 307, 308):
                        location = response.getheader('Location')
                        log_info(f"Redirect {response.status} -> {location}")
                        if location:
                            if not location.startswith('http'):
                                location = urljoin(current_url, location)
                            current_url = location
                            redirect_count += 1
                            response.close()
                            conn.close()
                            continue
                    
                    return HTTPResponse(response, conn, current_url)
                    
                except ssl.SSLError as e:
                    log_error(f"SSL Error: {e}")
                    if conn:
                        try:
                            conn.close()
                        except:
                            pass
                    raise
                    
                except socket.timeout as e:
                    log_error(f"Socket timeout: {e}")
                    if conn:
                        try:
                            conn.close()
                        except:
                            pass
                    raise
                    
                except socket.error as e:
                    log_error(f"Socket error: {e}")
                    if conn:
                        try:
                            conn.close()
                        except:
                            pass
                    raise
                    
            except Exception as e:
                log_exception(f"Erro HTTP para {current_url}")
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
        log_debug(f"HTTPResponse criado: status={self.status_code}, url={final_url}")
    
    @property
    def content(self):
        if self._content is None:
            log_debug("Lendo content completo...")
            self._content = self._response.read()
            log_debug(f"Content lido: {len(self._content)} bytes")
        return self._content
    
    def iter_content(self, chunk_size=4096):
        """Itera sobre o conteúdo em chunks"""
        total_bytes = 0
        chunk_count = 0
        try:
            while True:
                chunk = self._response.read(chunk_size)
                if not chunk:
                    log_debug(f"Stream finalizado: {chunk_count} chunks, {total_bytes} bytes")
                    break
                total_bytes += len(chunk)
                chunk_count += 1
                if chunk_count % 100 == 0:  # Log a cada 100 chunks
                    log_debug(f"Streaming: {chunk_count} chunks, {total_bytes} bytes")
                yield chunk
        except Exception as e:
            log_error(f"Erro no iter_content após {chunk_count} chunks, {total_bytes} bytes: {e}")
            raise
    
    def close(self):
        try:
            self._response.close()
            self._connection.close()
            log_debug("HTTPResponse fechado")
        except Exception as e:
            log_debug(f"Erro ao fechar HTTPResponse: {e}")


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
    log_debug(f"Reescrevendo m3u8, base_url={base_url}")
    
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
            log_debug(f"Erro ao reescrever URL {segment_url}: {e}")
            return segment_url
    
    result = re.sub(r'^(?!#)\S+', replace_url, playlist_content, flags=re.MULTILINE)
    log_debug(f"m3u8 reescrito: {len(playlist_content)} -> {len(result)} bytes")
    return result


def rewrite_m3u_playlist(playlist_content, proxy_host):
    """Reescreve URLs em uma lista M3U/M3U8 para passar pelo proxy."""
    log_debug(f"Reescrevendo playlist M3U, proxy_host={proxy_host}")
    
    lines = playlist_content.split('\n')
    rewritten_lines = []
    url_count = 0
    
    for line in lines:
        line = line.strip()
        
        if not line:
            rewritten_lines.append(line)
            continue
        
        if line.startswith('#'):
            rewritten_lines.append(line)
            continue
        
        if line.startswith('http://') or line.startswith('https://'):
            # FIX LISTA ONEPLAY
            #proxied_url = f"http://{proxy_host}/hlsretry?url={quote(line)}"
            proxied_url = f"http://{proxy_host}/hlsretry?url={line}"
            rewritten_lines.append(proxied_url)
            url_count += 1
        else:
            rewritten_lines.append(line)
    
    log_debug(f"Playlist reescrita: {url_count} URLs proxiadas")
    return '\n'.join(rewritten_lines)


def fetch_oneplay_list(list_url, proxy_host):
    """Baixa a lista OnePlay e reescreve as URLs com o proxy."""
    log_info(f"=== FETCH ONEPLAY LIST ===")
    log_info(f"URL: {list_url}")
    log_info(f"Proxy host: {proxy_host}")
    
    http_client = SimpleHTTPClient(timeout=15)
    
    try:
        response = http_client.request(list_url)
        
        if response.status_code == 200:
            content = response.content.decode('utf-8', errors='ignore')
            response.close()
            
            log_info(f"Lista baixada: {len(content)} bytes")
            log_debug(f"Primeiros 500 chars:\n{content[:500]}")
            
            rewritten = rewrite_m3u_playlist(content, proxy_host)
            
            log_info("Lista processada com sucesso")
            return rewritten
        else:
            response.close()
            log_error(f"Erro ao baixar lista: HTTP {response.status_code}")
            return None
            
    except Exception as e:
        log_exception(f"Erro ao baixar lista OnePlay")
        return None


def stream_response(response, client_ip, url):
    """Stream de resposta com cache"""
    log_debug(f"Iniciando stream_response para {url[:50]}...")
    
    cache_key = get_cache_key(client_ip, url) if any(ext in url.lower() for ext in ['.mp4', '.m3u8']) else client_ip
    is_ts = '.ts' in url.lower() or '/hl' in url.lower()
    
    bytes_read = 0
    chunk_count = 0
    
    try:
        for chunk in response.iter_content(chunk_size=4096):
            if chunk:
                bytes_read += len(chunk)
                chunk_count += 1
                
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
                
        log_debug(f"Stream completo: {chunk_count} chunks, {bytes_read} bytes")
        
    except Exception as e:
        log_error(f"Erro no stream após {chunk_count} chunks, {bytes_read} bytes: {e}")
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
        log_debug(f"Streaming do cache: {len(cache[cache_key])} chunks")
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
    
    request_id = random_hex(8)  # ID único para esta requisição
    log_info(f"")
    log_info(f"{'='*60}")
    log_info(f"[REQ-{request_id}] Nova conexão de {client_address[0]}:{client_address[1]}")
    log_info(f"{'='*60}")
    
    http_client = SimpleHTTPClient(timeout=15)
    
    try:
        client_socket.settimeout(30)  # Aumentar timeout
        
        log_debug(f"[REQ-{request_id}] Aguardando dados...")
        request_data = client_socket.recv(8192).decode('utf-8', errors='ignore')
        
        if not request_data:
            log_debug(f"[REQ-{request_id}] Sem dados recebidos")
            return
        
        log_debug(f"[REQ-{request_id}] Dados recebidos: {len(request_data)} bytes")
        log_debug(f"[REQ-{request_id}] Request:\n{request_data[:500]}")
        
        method, path, headers = parse_http_request(request_data)
        
        if not method or not path:
            log_error(f"[REQ-{request_id}] Falha ao parsear request")
            return
        
        log_info(f"[REQ-{request_id}] {method} {path}")
        log_debug(f"[REQ-{request_id}] Headers: {headers}")
        
        if method != 'GET':
            log_debug(f"[REQ-{request_id}] Método não permitido: {method}")
            client_socket.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return
        
        # Parse path e query params
        if '?' in path:
            path_part, query_string = path.split('?', 1)
            query_params = parse_qs(query_string)
        else:
            path_part = path
            query_params = {}
        
        log_debug(f"[REQ-{request_id}] Path: {path_part}, Params: {query_params}")
        
        client_ip = get_ip(headers, client_address)
        proxy_host = f"{LOCAL_IP}:{PORT}"
        
        # ===== ROTA: / =====
        if path_part == "/":
            log_info(f"[REQ-{request_id}] Rota: /")
            response_data = {
                "message": "ONEPLAY PROXY - QPython LAN Edition (DEBUG)",
                "status": "running",
                "local_ip": LOCAL_IP,
                "port": PORT,
                "python_version": sys.version,
                "endpoints": {
                    "status": f"http://{proxy_host}/",
                    "oneplay": f"http://{proxy_host}/oneplay",
                    "test": f"http://{proxy_host}/test",
                    "hlsretry": f"http://{proxy_host}/hlsretry?url=<URL>",
                    "stop": f"http://{proxy_host}/stop"
                },
                "listas_disponiveis": list(ONEPLAY_LISTS.keys())
            }
            response = json.dumps(response_data, indent=2)
            client_socket.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
                response.encode('utf-8')
            )
            log_info(f"[REQ-{request_id}] Resposta enviada: 200 OK")
        
        # ===== ROTA: /test - Teste de conectividade =====
        elif path_part == "/test":
            log_info(f"[REQ-{request_id}] Rota: /test")
            
            test_results = {
                "dns_test": {},
                "http_test": {},
                "ssl_test": {}
            }
            
            # Teste DNS
            log_info(f"[REQ-{request_id}] Testando DNS...")
            dns = CustomDNS()
            test_domains = ['google.com', 'cloudflare.com', 'oneplayhd.com']
            for domain in test_domains:
                for dns_server in CustomDNS.DNS_SERVERS[:2]:
                    try:
                        ip = dns.resolve(domain, dns_server)
                        test_results["dns_test"][f"{domain}@{dns_server}"] = ip or "FAILED"
                    except Exception as e:
                        test_results["dns_test"][f"{domain}@{dns_server}"] = f"ERROR: {e}"
            
            # Teste HTTP
            log_info(f"[REQ-{request_id}] Testando HTTP...")
            test_urls = [
                ('http://httpbin.org/get', 'HTTP'),
                ('https://httpbin.org/get', 'HTTPS'),
            ]
            for url, name in test_urls:
                try:
                    start = time.time()
                    resp = http_client.request(url)
                    elapsed = time.time() - start
                    test_results["http_test"][name] = {
                        "status": resp.status_code,
                        "time_ms": round(elapsed * 1000),
                        "ok": resp.status_code == 200
                    }
                    resp.close()
                except Exception as e:
                    test_results["http_test"][name] = {"error": str(e)}
            
            response = json.dumps(test_results, indent=2)
            client_socket.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
                response.encode('utf-8')
            )
            log_info(f"[REQ-{request_id}] Teste concluído")
        
        # ===== ROTA: /stop =====
        elif path_part == "/stop":
            log_info(f"[REQ-{request_id}] Rota: /stop")
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
            log_info(f"[REQ-{request_id}] Rota: /oneplay")
            
            lista_param = query_params.get('lista', [None])[0]
            
            if lista_param and lista_param in ONEPLAY_LISTS:
                list_url = ONEPLAY_LISTS[lista_param]
            else:
                list_url = DEFAULT_ONEPLAY_LIST
            
            log_info(f"[REQ-{request_id}] Baixando lista: {list_url}")
            
            rewritten_playlist = fetch_oneplay_list(list_url, proxy_host)
            
            if rewritten_playlist:
                response_headers = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain; charset=utf-8\r\n"
                    b"Content-Disposition: inline; filename=\"oneplay.m3u\"\r\n"
                    b"Cache-Control: no-cache\r\n"
                    b"\r\n"
                )
                client_socket.sendall(response_headers + rewritten_playlist.encode('utf-8'))
                log_info(f"[REQ-{request_id}] Lista enviada: {len(rewritten_playlist)} bytes")
            else:
                error_response = json.dumps({
                    "error": "Falha ao baixar lista OnePlay",
                    "url": list_url,
                    "request_id": request_id
                })
                client_socket.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\n\r\n" +
                    error_response.encode('utf-8')
                )
                log_error(f"[REQ-{request_id}] Erro 502 - Falha ao baixar lista")
        
        # ===== ROTA: /hlsretry =====
        elif path_part == "/hlsretry":
            log_info(f"[REQ-{request_id}] Rota: /hlsretry")
            
            url = query_params.get('url', [None])[0]
            if url:
                try:
                    url = unquote_plus(url)
                except:
                    pass
            
            log_info(f"[REQ-{request_id}] URL alvo: {url}")
            
            if not url:
                log_error(f"[REQ-{request_id}] URL não fornecida")
                client_socket.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\nNo URL provided")
                return
            
            cache_key = get_cache_key(client_ip, url) if any(x in url.lower() for x in ['.mp4', '.m3u8']) else client_ip
            
            req_headers = {k: v for k, v in headers.items() if k.lower() != 'host'}
            original_ua = req_headers.get('User-Agent', DEFAULT_USER_AGENT)
            
            max_retries = 5
            attempts = 0
            tried_without_range = False
            change_user_agent = False
            last_error = None
            
            media_type = (
                'video/mp4' if '.mp4' in url.lower()
                else 'video/mp2t' if '.ts' in url.lower() or '/hl' in url.lower()
                else 'application/vnd.apple.mpegurl' if '.m3u8' in url.lower()
                else 'application/octet-stream'
            )
            response_headers = {}
            status = 200
            
            while attempts < max_retries:
                log_info(f"[REQ-{request_id}] Tentativa {attempts + 1}/{max_retries}")
                
                try:
                    if '.mp4' in url.lower() and 'Range' in req_headers and tried_without_range:
                        del req_headers['Range']
                        log_debug(f"[REQ-{request_id}] Removido header Range")
                    
                    # User-Agent handling
                    if AGENT_OF_CHAOS.get(cache_key) and not ('.ts' in url.lower() or '/hl' in url.lower()):
                        if change_user_agent:
                            req_headers['User-Agent'] = AGENT_OF_CHAOS[cache_key]
                    elif '.ts' in url.lower() or '/hl' in url.lower():
                        if change_user_agent or 'User-Agent' not in req_headers:
                            req_headers['User-Agent'] = random_hex(32)
                        else:
                            req_headers['User-Agent'] = original_ua
                    
                    log_debug(f"[REQ-{request_id}] Fazendo request para: {url[:80]}...")
                    response = http_client.request(url, headers=req_headers, stream=True)
                    
                    log_info(f"[REQ-{request_id}] Response: {response.status_code}")
                    
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
                        log_debug(f"[REQ-{request_id}] Content-Type: {content_type}")
                        
                        # Processar m3u8
                        if "mpegurl" in content_type or ".m3u8" in url.lower():
                            log_info(f"[REQ-{request_id}] Processando como M3U8")
                            base_url = url.rsplit('/', 1)[0]
                            playlist_content = response.content.decode('utf-8', errors='ignore')
                            
                            log_debug(f"[REQ-{request_id}] M3U8 content ({len(playlist_content)} bytes):\n{playlist_content[:500]}")
                            
                            rewritten = rewrite_m3u8_urls(playlist_content, base_url, 'http', proxy_host)
                            client_socket.sendall(
                                b"HTTP/1.1 200 OK\r\nContent-Type: application/vnd.apple.mpegurl\r\n\r\n" +
                                rewritten.encode('utf-8')
                            )
                            log_info(f"[REQ-{request_id}] M3U8 enviado: {len(rewritten)} bytes")
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
                            if k.lower() in ['content-type', 'accept-ranges', 'content-range', 'content-length']
                        }
                        status = 206 if response.status_code == 206 else 200
                        
                        header_str = f"HTTP/1.1 {status} OK\r\n"
                        for k, v in response_headers.items():
                            header_str += f"{k}: {v}\r\n"
                        header_str += f"Content-Type: {media_type}\r\n\r\n"
                        
                        log_debug(f"[REQ-{request_id}] Enviando headers: {header_str[:200]}")
                        client_socket.sendall(header_str.encode('utf-8'))
                        
                        log_info(f"[REQ-{request_id}] Iniciando stream...")
                        bytes_sent = 0
                        for chunk in stream_response(response, client_ip, url):
                            try:
                                client_socket.sendall(chunk)
                                bytes_sent += len(chunk)
                            except (BrokenPipeError, ConnectionResetError) as e:
                                log_info(f"[REQ-{request_id}] Cliente desconectou após {bytes_sent} bytes")
                                return
                        
                        log_info(f"[REQ-{request_id}] Stream completo: {bytes_sent} bytes")
                        return
                    
                    elif response.status_code == 416 and 'Range' in req_headers and not tried_without_range:
                        log_debug(f"[REQ-{request_id}] Erro 416, tentando sem Range")
                        tried_without_range = True
                        response.close()
                        continue
                    
                    else:
                        change_user_agent = True
                        last_error = f"HTTP {response.status_code}"
                        log_info(f"[REQ-{request_id}] Erro {response.status_code}, tentativa {attempts + 1}")
                        AGENT_OF_CHAOS[cache_key] = random_hex(32)
                        response.close()
                        time.sleep(1)
                        attempts += 1
                        
                        if attempts >= max_retries:
                            # Tentar cache
                            if any(x in url.lower() for x in ['.ts', '/hl', '.mp4']):
                                cached_chunks = list(stream_cache(client_ip, url) or [])
                                if cached_chunks:
                                    log_info(f"[REQ-{request_id}] Usando cache: {len(cached_chunks)} chunks")
                                    header_str = f"HTTP/1.1 200 OK\r\nContent-Type: {media_type}\r\n\r\n"
                                    client_socket.sendall(header_str.encode('utf-8'))
                                    for chunk in cached_chunks:
                                        try:
                                            client_socket.sendall(chunk)
                                        except:
                                            break
                                    return
                
                except Exception as e:
                    change_user_agent = True
                    last_error = str(e)
                    log_exception(f"[REQ-{request_id}] Erro na tentativa {attempts + 1}")
                    AGENT_OF_CHAOS[cache_key] = random_hex(32)
                    time.sleep(1)
                    attempts += 1
            
            # Todas tentativas falharam
            log_error(f"[REQ-{request_id}] Todas as {max_retries} tentativas falharam. Último erro: {last_error}")
            
            error_response = json.dumps({
                "error": "Failed after multiple attempts",
                "attempts": max_retries,
                "last_error": last_error,
                "url": url[:100],
                "request_id": request_id
            })
            client_socket.sendall(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\n\r\n" +
                error_response.encode('utf-8')
            )
        
        # ===== ROTA NÃO ENCONTRADA =====
        else:
            log_info(f"[REQ-{request_id}] Rota não encontrada: {path_part}")
            client_socket.sendall(b"HTTP/1.1 404 Not Found\r\n\r\nNot Found")
    
    except socket.timeout:
        log_debug(f"[REQ-{request_id}] Socket timeout")
    except Exception as e:
        log_exception(f"[REQ-{request_id}] Erro ao processar requisição")
    finally:
        try:
            client_socket.close()
        except:
            pass
        log_info(f"[REQ-{request_id}] Conexão fechada")
        log_info(f"{'='*60}\n")


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
    print("##### ONEPLAY PROXY #####")
    print("=" * 60)
    print("         PROXY HLS - LAN Edition (DEBUG MODE)")
    print("=" * 60)
    print(f"\n  🌐 IP Local (LAN): {local_ip}")
    print(f"  🔌 Porta: {port}")
    print(f"  🐍 Python: {sys.version.split()[0]}")
    print(f"\n  📡 URLs de Acesso:")
    print(f"\n  🎬 Endpoints Disponíveis:")
    print(f"     • http://{local_ip}:{port}/oneplay  - Lista IPTV com proxy")
    print(f"     • /hlsretry?url=<URL>     - Proxy HLS com retry")
    print(f"     • /stop                   - Parar o servidor")
    print(f"\n  🔧 DEBUG MODE ATIVADO - Logs detalhados no console")
    print(f"\n  ⌨️  Pressione Ctrl+C para parar o servidor")
    print("=" * 60 + "\n")


def start_proxy():
    """Inicia o servidor proxy"""
    global SHUTDOWN_EVENT, LOCAL_IP
    
    print("\n🚀 Iniciando proxy...")
    
    if is_proxy_running():
        print(f"\n❌ Proxy já está rodando na porta {PORT}")
        return False
    
    # Obter IP local
    LOCAL_IP = get_local_ip()
    print(f"📍 IP Local detectado: {LOCAL_IP}")
    
    # Inicializar DNS customizado
    print("🔧 Inicializando DNS customizado...")
    CustomDNS()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind(('0.0.0.0', PORT))
        server_socket.listen(10)
        server_socket.settimeout(1)
        print(f"✅ Socket criado e escutando em 0.0.0.0:{PORT}")
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
                thread = threading.Thread(
                    target=handle_request,
                    args=(client_socket, client_address, server_socket),
                    name=f"Handler-{client_address[0]}:{client_address[1]}"
                )
                thread.daemon = True
                thread.start()
            except socket.timeout:
                continue
            except socket.error as e:
                if not SHUTDOWN_EVENT.is_set():
                    log_error(f"Erro ao aceitar conexão: {e}")
    
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


# ============== MAIN ==============
if __name__ == '__main__':
    start_proxy()
