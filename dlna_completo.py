# -*- coding: utf-8 -*-
"""
Proxy HTTP com DNS Customizado para QPython/Android
Python 3.6+ - Sem dependências externas
Versão LAN - Acessível de outros dispositivos na rede
COM PLAYER HLS INTEGRADO
COM SUPORTE DLNA + CHROMECAST
"""

import json
import socket
import struct
import random
import threading
import time
import re
import ssl
import traceback
import sys
import os
from urllib.parse import urljoin, urlparse, parse_qs, unquote_plus, quote, unquote
from http.client import HTTPConnection, HTTPSConnection
import urllib.request
import urllib.parse
import urllib.error
import hashlib
import http.server
import socketserver

# ============== CONFIGURAÇÃO ==============
PORT = 8094
PROXY_PORT = 8888  # Porta para o proxy DLNA
DEFAULT_USER_AGENT = "Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 Chrome/130.0.0.0 Mobile Safari/537.36"

# URLs das listas OnePlay
ONEPLAY_LISTS = {
    'lista01': '\x68\x74\x74\x70\x73\x3a\x2f\x2f\x6f\x6e\x65\x70\x6c\x61\x79\x68\x64\x2e\x63\x6f\x6d\x2f\x6c\x69\x73\x74\x61\x73\x5f\x6f\x6e\x65\x70\x6c\x61\x79\x2f\x6c\x69\x73\x74\x61\x30\x31\x2e\x74\x78\x74',
    'lista02': '\x68\x74\x74\x70\x73\x3a\x2f\x2f\x6f\x6e\x65\x70\x6c\x61\x79\x68\x64\x2e\x63\x6f\x6d\x2f\x6c\x69\x73\x74\x61\x73\x5f\x6f\x6e\x65\x70\x6c\x61\x79\x2f\x6c\x69\x73\x74\x61\x30\x32\x2e\x74\x78\x74',
    'lista03': '\x68\x74\x74\x70\x73\x3a\x2f\x2f\x6f\x6e\x65\x70\x6c\x61\x79\x68\x64\x2e\x63\x6f\x6d\x2f\x6c\x69\x73\x74\x61\x73\x5f\x6f\x6e\x65\x70\x6c\x61\x79\x2f\x6c\x69\x73\x74\x61\x30\x33\x2e\x74\x78\x74',
    'lista04': '\x68\x74\x74\x70\x73\x3a\x2f\x2f\x6f\x6e\x65\x70\x6c\x61\x79\x68\x64\x2e\x63\x6f\x6d\x2f\x6c\x69\x73\x74\x61\x73\x5f\x6f\x6e\x65\x70\x6c\x61\x79\x2f\x6c\x69\x73\x74\x61\x30\x34\x2e\x74\x78\x74',
    'lista05': '\x68\x74\x74\x70\x73\x3a\x2f\x2f\x6f\x6e\x65\x70\x6c\x61\x79\x68\x64\x2e\x63\x6f\x6d\x2f\x6c\x69\x73\x74\x61\x73\x5f\x6f\x6e\x65\x70\x6c\x61\x79\x2f\x6c\x69\x73\x74\x61\x30\x35\x2e\x74\x78\x74',
    'lista06': '\x68\x74\x74\x70\x73\x3a\x2f\x2f\x6f\x6e\x65\x70\x6c\x61\x79\x68\x64\x2e\x63\x6f\x6d\x2f\x6c\x69\x73\x74\x61\x73\x5f\x6f\x6e\x65\x70\x6c\x61\x79\x2f\x6c\x69\x73\x74\x61\x30\x36\x2e\x74\x78\x74',
    'lista07': '\x68\x74\x74\x70\x73\x3a\x2f\x2f\x6f\x6e\x65\x70\x6c\x61\x79\x68\x64\x2e\x63\x6f\x6d\x2f\x6c\x69\x73\x74\x61\x73\x5f\x6f\x6e\x65\x70\x6c\x61\x79\x2f\x6c\x69\x73\x74\x61\x30\x37\x2e\x74\x78\x74',
    'lista08': '\x68\x74\x74\x70\x73\x3a\x2f\x2f\x6f\x6e\x65\x70\x6c\x61\x79\x68\x64\x2e\x63\x6f\x6d\x2f\x6c\x69\x73\x74\x61\x73\x5f\x6f\x6e\x65\x70\x6c\x61\x79\x2f\x6c\x69\x73\x74\x61\x30\x38\x2e\x74\x78\x74',
    'lista09': '\x68\x74\x74\x70\x73\x3a\x2f\x2f\x6f\x6e\x65\x70\x6c\x61\x79\x68\x64\x2e\x63\x6f\x6d\x2f\x6c\x69\x73\x74\x61\x73\x5f\x6f\x6e\x65\x70\x6c\x61\x79\x2f\x6c\x69\x73\x74\x61\x30\x39\x2e\x74\x78\x74',
    'lista10': '\x68\x74\x74\x70\x73\x3a\x2f\x2f\x6f\x6e\x65\x70\x6c\x61\x79\x68\x64\x2e\x63\x6f\x6d\x2f\x6c\x69\x73\x74\x61\x73\x5f\x6f\x6e\x65\x70\x6c\x61\x79\x2f\x6c\x69\x73\x74\x61\x31\x30\x2e\x74\x78\x74'
}
DEFAULT_ONEPLAY_LIST = ONEPLAY_LISTS['lista01']

# ============== ESTADO GLOBAL ==============
IP_CACHE_TS = {}
IP_CACHE_MP4 = {}
AGENT_OF_CHAOS = {}
COUNT_CLEAR = {}
SHUTDOWN_EVENT = threading.Event()
LOCAL_IP = None

# DLNA globals
active_streams = {}
active_sessions_lock = threading.Lock()

# Chromecast globals
active_chromecast_controllers = {}
CHROMECAST_ENABLED = False

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
                
                conn = None
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
                    
                except:
                    if conn:
                        try:
                            conn.close()
                        except:
                            pass
                    raise
                    
            except Exception as e:
                if redirect_count >= max_redirects:
                    raise Exception(f"Muitos redirects para {url}: {e}")
                redirect_count += 1
        
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
        try:
            while True:
                chunk = self._response.read(chunk_size)
                if not chunk:
                    break
                yield chunk
        except Exception as e:
            raise
    
    def close(self):
        try:
            self._response.close()
            self._connection.close()
        except:
            pass

def import_chromecast():
    global CHROMECAST_ENABLED
    try:
        http_client = SimpleHTTPClient(timeout=15)
        res_code = http_client.request('https://raw.githack.com/zoreu/stream_roku/main/chromecast_support.py')
        
        if res_code.status_code == 200:
            code = res_code.content.decode('utf-8', errors='ignore')
            res_code.close()
            CHROMECAST_ENABLED = True
            exec(code, globals())  # carrega tudo no global
            return True
        else:
            CHROMECAST_ENABLED = False
            return False
    except:
        CHROMECAST_ENABLED = False
        return False

import_chromecast()


# Tentar carregar módulo Chromecast
# try:
#     sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'libs'))
#     import chromecast_support
#     CHROMECAST_ENABLED = True
#     print("✅ Módulo Chromecast carregado com sucesso.")
# except ImportError as e:
#     print(f"⚠️  Aviso: Não foi possível carregar o módulo Chromecast: {e}")
#     print("   A funcionalidade de transmissão para Chromecast estará desativada.")

TIMEOUT = 10
SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SSDP_MX = 3

# ============== FUNÇÕES AUXILIARES ==============
def basename(p):
    """Returns the final component of a pathname"""
    i = p.rfind('/') + 1
    return p[i:]

def convert_to_m3u8(url):
    """Converte URL para formato M3U8"""
    if '|' in url:
        url = url.split('|')[0]
    elif '%7C' in url:
        url = url.split('%7C')[0]
    
    if not '.m3u8' in url and not '/hl' in url and int(url.count("/")) > 4 and not '.mp4' in url and not '.avi' in url:
        parsed_url = urlparse(url)
        try:
            host_part1 = '%s://%s'%(parsed_url.scheme,parsed_url.netloc)
            host_part2 = url.split(host_part1)[1]
            url = host_part1 + '/live' + host_part2
            file = basename(url)
            if '.ts' in file:
                file_new = file.replace('.ts', '.m3u8')
                url = url.replace(file, file_new)
            else:
                url = url + '.m3u8'
        except:
            pass
    return url 

def get_local_ip():
    """Obtém o IP local da LAN"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except:
        pass
    
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip and not ip.startswith("127."):
            return ip
    except:
        pass
    
    return "127.0.0.1"


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
            return segment_url
    
    result = re.sub(r'^(?!#)\S+', replace_url, playlist_content, flags=re.MULTILINE)
    return result

def rewrite_m3u_playlist(playlist_content, proxy_host):
    """Reescreve URLs em uma lista M3U/M3U8 para passar pelo proxy."""
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
            proxied_url = f"http://{proxy_host}/hlsretry?url={line}"
            rewritten_lines.append(proxied_url)
            url_count += 1
        else:
            rewritten_lines.append(line)
    
    return '\n'.join(rewritten_lines)

def fetch_oneplay_list(list_url, proxy_host):
    """Baixa a lista OnePlay e reescreve as URLs com o proxy."""
    http_client = SimpleHTTPClient(timeout=15)
    
    try:
        response = http_client.request(list_url)
        
        if response.status_code == 200:
            content = response.content.decode('utf-8', errors='ignore')
            response.close()
            
            rewritten = rewrite_m3u_playlist(content, proxy_host)
            return rewritten
        else:
            response.close()
            return None
            
    except Exception as e:
        return None

def stream_response(response, client_ip, url):
    """Stream de resposta com cache"""
    cache_key = get_cache_key(client_ip, url) if any(ext in url.lower() for ext in ['.mp4', '.m3u8']) else client_ip
    is_ts = '.ts' in url.lower() or '/hl' in url.lower()
    
    try:
        for chunk in response.iter_content(chunk_size=4096):
            if chunk:
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
        cache = IP_CACHE_TS if is_ts else IP_CACHE_MP4
        for chunk in cache.get(cache_key, [])[-5:]:
            yield chunk
    finally:
        try:
            response.close()
        except:
            pass

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

# ============== DLNA IMPLEMENTAÇÃO ==============

def test_port_open(ip, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

class SimpleXMLParser:
    @staticmethod
    def find_tag_content(xml_str, tag_name):
        patterns = [
            rf'<(?:\w+:)?{tag_name}[^>]*>([^<]*)</(?:\w+:)?{tag_name}>',
            rf'<{tag_name}[^>]*>([^<]*)</{tag_name}>',
        ]
        for pattern in patterns:
            match = re.search(pattern, xml_str, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).strip()
        return None
    
    @staticmethod
    def find_all_services(xml_str):
        services = []
        pattern = r'<(?:\w+:)?service[^>]*>(.*?)</(?:\w+:)?service>'
        matches = re.findall(pattern, xml_str, re.IGNORECASE | re.DOTALL)
        for match in matches:
            services.append({
                'serviceType': SimpleXMLParser.find_tag_content(match, 'serviceType'),
                'controlURL': SimpleXMLParser.find_tag_content(match, 'controlURL'),
            })
        return services

# ============== SERVIDOR PROXY COM SUPORTE HEAD ==============

class StreamProxyHandler(http.server.BaseHTTPRequestHandler):
    """Proxy com suporte a HEAD, GET, OPTIONS para compatibilidade com LG WebOS"""
    
    protocol_version = 'HTTP/1.1'
    
    def log_message(self, format, *args):
        pass
    
    def log_request(self, code='-', size='-'):
        print(f"   [DLNA Proxy] {self.command} {self.path} → {code}")
    
    def _send_cors_headers(self):
        """Envia headers CORS para compatibilidade"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.send_header('Access-Control-Expose-Headers', '*')
    
    def do_OPTIONS(self):
        """Responde a preflight CORS"""
        self.send_response(200)
        self._send_cors_headers()
        self.send_header('Content-Length', '0')
        self.end_headers()
    
    def do_HEAD(self):
        """Responde a requisições HEAD (LG WebOS faz isso primeiro!)"""
        self._handle_request(head_only=True)
    
    def do_GET(self):
        """Responde a requisições GET"""
        self._handle_request(head_only=False)
    
    def _handle_request(self, head_only=False):
        """Processa requisições GET e HEAD"""
        try:
            if self.path == '/test':
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self._send_cors_headers()
                self.send_header('Content-Length', '9')
                self.end_headers()
                if not head_only:
                    self.wfile.write(b"Proxy OK!")
                return
            
            if self.path.startswith('/stream/'):
                parts = self.path.rstrip('/').split('/')
                if len(parts) >= 3:
                    stream_id = parts[2]
                    chunk_path = '/'.join(parts[3:]) if len(parts) > 3 else ''
                    
                    if chunk_path:
                        self._serve_chunk(stream_id, chunk_path, head_only)
                    else:
                        self._serve_m3u8(stream_id, head_only)
                    return
            
            self.send_error(404, "Not found")
            
        except BrokenPipeError:
            pass
        except ConnectionResetError:
            pass
        except Exception as e:
            print(f"   [DLNA Proxy Error] {e}")
            try:
                self.send_error(500, str(e))
            except:
                pass
    
    def _serve_m3u8(self, stream_id, head_only=False):
        """Serve arquivo M3U8"""
        if stream_id not in active_streams:
            self.send_error(404, "Stream não encontrado")
            return
        
        original_url = active_streams[stream_id]['url']
        
        if head_only:
            self.send_response(200)
            self.send_header('Content-Type', 'application/vnd.apple.mpegurl')
            self._send_cors_headers()
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.end_headers()
            return
        
        content = self._fetch_url(original_url)
        if content is None:
            self.send_error(502, "Erro ao buscar stream")
            return
        
        modified = self._rewrite_m3u8(content, stream_id, original_url)
        data = modified.encode('utf-8')
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/vnd.apple.mpegurl')
        self._send_cors_headers()
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()
        self.wfile.write(data)
    
    def _serve_chunk(self, stream_id, chunk_path, head_only=False):
        """Serve chunks de vídeo ou playlists secundárias"""
        if stream_id not in active_streams:
            self.send_error(404, "Stream não encontrado")
            return
        
        base_url = active_streams[stream_id]['base_url']
        chunk_path = urllib.parse.unquote(chunk_path)
        
        if chunk_path.startswith('http://') or chunk_path.startswith('https://'):
            chunk_url = chunk_path
        elif chunk_path.startswith('/'):
            parsed = urllib.parse.urlparse(active_streams[stream_id]['url'])
            chunk_url = f"{parsed.scheme}://{parsed.netloc}{chunk_path}"
        else:
            chunk_url = base_url + chunk_path
        
        if '.m3u8' in chunk_path.lower():
            if head_only:
                self.send_response(200)
                self.send_header('Content-Type', 'application/vnd.apple.mpegurl')
                self._send_cors_headers()
                self.end_headers()
                return
            
            content = self._fetch_url(chunk_url)
            if content:
                new_base = chunk_url.rsplit('/', 1)[0] + '/'
                active_streams[stream_id]['base_url'] = new_base
                modified = self._rewrite_m3u8(content, stream_id, chunk_url)
                data = modified.encode('utf-8')
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/vnd.apple.mpegurl')
                self._send_cors_headers()
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            else:
                self.send_error(502, "Erro ao buscar playlist")
                return
        
        self._proxy_binary(chunk_url, head_only)
    
    def _proxy_binary(self, url, head_only=False):
        try:
            ctx = ssl._create_unverified_context()
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept-Encoding': 'identity',
            }
            
            if 'Range' in self.headers:
                headers['Range'] = self.headers['Range']
            
            req = urllib.request.Request(url, headers=headers, method='GET' if not head_only else 'HEAD')
            
            with urllib.request.urlopen(req, timeout=30, context=ctx) as response:
                headers = response.headers
                
                ct = headers.get('Content-Type', '')
                if 'ts' in url.lower() or 'm4s' in url.lower():
                    ct = 'video/MP2T'
                elif '.m3u8' in url.lower():
                    ct = 'application/vnd.apple.mpegurl'
                
                status = 200
                if 'Range' in headers.get('Content-Range', '') or response.code == 206:
                    status = 206
                
                self.send_response(status)
                self.send_header('Content-Type', ct)
                self.send_header('Accept-Ranges', 'bytes')
                self.send_header('Connection', 'keep-alive')
                self._send_cors_headers()
                
                cl = headers.get('Content-Length')
                if cl:
                    self.send_header('Content-Length', cl)
                
                if 'Content-Range' in headers:
                    self.send_header('Content-Range', headers['Content-Range'])
                
                self.end_headers()
                
                if head_only or self.command == 'HEAD':
                    return
                
                while True:
                    chunk = response.read(128*1024)
                    if not chunk:
                        break
                    try:
                        self.wfile.write(chunk)
                    except:
                        break
                    
        except urllib.error.HTTPError as e:
            if e.code == 416:
                self.send_error(416, "Range Not Satisfiable")
            else:
                self.send_error(e.code, str(e))
        except Exception as e:
            print(f"   [Proxy Error] Binary: {e}")
            try:
                self.send_error(502, "Bad Gateway")
            except:
                pass
    
    def _fetch_url(self, url):
        """Busca conteúdo de URL"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': '*/*',
            }
            
            req = urllib.request.Request(url, headers=headers)
            
            if url.startswith('https'):
                response = urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx)
            else:
                response = urllib.request.urlopen(req, timeout=TIMEOUT)
            
            return response.read().decode('utf-8', errors='ignore')
        except Exception as e:
            print(f"   [Proxy Error] Fetch: {e}")
            return None
    
    def _rewrite_m3u8(self, content, stream_id, original_url):
        """Reescreve URLs no M3U8"""
        lines = content.split('\n')
        new_lines = []
        
        base_url = original_url.rsplit('/', 1)[0] + '/'
        active_streams[stream_id]['base_url'] = base_url
        
        for line in lines:
            line = line.strip()
            
            if not line:
                new_lines.append(line)
                continue
            
            if line.startswith('#'):
                if 'URI="' in line:
                    line = re.sub(
                        r'URI="([^"]+)"',
                        lambda m: f'URI="{self._make_proxy_url(m.group(1), stream_id, base_url)}"',
                        line
                    )
                new_lines.append(line)
            elif line.startswith('http://') or line.startswith('https://'):
                proxy_url = f"http://{LOCAL_IP}:{PROXY_PORT}/stream/{stream_id}/{urllib.parse.quote(line, safe='')}"
                new_lines.append(proxy_url)
            elif not line.startswith('#'):
                proxy_url = f"http://{LOCAL_IP}:{PROXY_PORT}/stream/{stream_id}/{urllib.parse.quote(line, safe='')}"
                new_lines.append(proxy_url)
            else:
                new_lines.append(line)
        
        return '\n'.join(new_lines)
    
    def _make_proxy_url(self, url, stream_id, base_url):
        if url.startswith('http://') or url.startswith('https://'):
            full_url = url
        else:
            full_url = urllib.parse.urljoin(base_url, url)
        return f"http://{LOCAL_IP}:{PROXY_PORT}/stream/{stream_id}/{urllib.parse.quote(full_url, safe='')}"

# ============== SERVIDOR DLNA PROXY ==============

dlna_proxy_ready = threading.Event()

def start_dlna_proxy_server():
    class ThreadedServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
    
    try:
        server = ThreadedServer(("0.0.0.0", PROXY_PORT), StreamProxyHandler)
        dlna_proxy_ready.set()
        print(f"   ✅ DLNA Proxy iniciado na porta {PROXY_PORT}")
        server.serve_forever()
    except Exception as e:
        print(f"   ❌ Erro no DLNA proxy: {e}")
        dlna_proxy_ready.set()

# ============== DLNA DESCOBERTA ==============

class DLNADiscovery:
    def __init__(self):
        self.devices = {}
        self.lock = threading.Lock()
    
    def discover(self, timeout=SSDP_MX):
        self.devices = {}
        
        for target in ["urn:schemas-upnp-org:device:MediaRenderer:1", 
                       "urn:schemas-upnp-org:service:AVTransport:1"]:
            self._search(target, timeout)
        
        return list(self.devices.values())
    
    def _search(self, target, timeout):
        msg = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            f"MX: {timeout}\r\n"
            f"ST: {target}\r\n"
            "\r\n"
        ).encode()
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
        sock.settimeout(2)
        
        try:
            sock.sendto(msg, (SSDP_ADDR, SSDP_PORT))
            
            start = time.time()
            while time.time() - start < 2:
                try:
                    data, addr = sock.recvfrom(8192)
                    self._parse(data.decode('utf-8', errors='ignore'), addr)
                except socket.timeout:
                    break
                except:
                    continue
        finally:
            sock.close()
    
    def _parse(self, response, addr):
        headers = {}
        for line in response.split('\r\n'):
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.upper().strip()] = v.strip()
        
        location = headers.get('LOCATION')
        if not location or location in self.devices:
            return
        
        info = self._get_info(location, addr[0])
        if info:
            with self.lock:
                self.devices[location] = info
    
    def _get_info(self, location, ip):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            req = urllib.request.Request(location, headers={'User-Agent': 'DLNA/1.0'})
            
            if location.startswith('https'):
                resp = urllib.request.urlopen(req, timeout=5, context=ctx)
            else:
                resp = urllib.request.urlopen(req, timeout=5)
            
            xml = resp.read().decode('utf-8', errors='ignore')
            
            name = SimpleXMLParser.find_tag_content(xml, 'friendlyName') or f"Device ({ip})"
            mfr = SimpleXMLParser.find_tag_content(xml, 'manufacturer') or ''
            model = SimpleXMLParser.find_tag_content(xml, 'modelName') or ''
            
            combined = f"{mfr} {model} {name} {xml}".lower()
            if 'webos' in combined or 'lg' in combined:
                tv_type = 'lg_webos'
            elif 'samsung' in combined or 'tizen' in combined:
                tv_type = 'samsung_tizen'
            elif 'roku' in combined:
                tv_type = 'roku'
            elif 'android' in combined or 'tcl' in combined:
                tv_type = 'android_tv'
            else:
                tv_type = 'generic'
            
            control = None
            for svc in SimpleXMLParser.find_all_services(xml):
                if svc.get('serviceType') and 'AVTransport' in svc['serviceType']:
                    url = svc.get('controlURL', '')
                    if url:
                        if url.startswith('http'):
                            control = url
                        else:
                            parsed = urllib.parse.urlparse(location)
                            base = f"{parsed.scheme}://{parsed.netloc}"
                            control = base + (url if url.startswith('/') else '/' + url)
                        break
            
            if not control:
                parsed = urllib.parse.urlparse(location)
                control = f"{parsed.scheme}://{parsed.netloc}/upnp/control/AVTransport1"
            
            print(f"  ✅ {name} ({tv_type}) - {ip}")
            
            return {
                'id': location, 'name': name, 'manufacturer': mfr,
                'model': model, 'ip': ip, 'location': location,
                'control_url': control, 'tv_type': tv_type
            }
        except:
            return None

# ============== CHROMECAST DESCOBERTA ==============

class ChromecastDiscovery:
    def discover(self, timeout=4):
        devices = []
        
        if not CHROMECAST_ENABLED:
            return devices
        
        try:
            # Usar o módulo chromecast_support para descobrir Chromecasts
            #casts = chromecast_support.discover_chromecasts(timeout=timeout)
            casts = discover_chromecasts(timeout=timeout)
            
            for cast in casts:
                devices.append({
                    'id': cast.get('id', cast.get('ip')),
                    'name': cast.get('name', 'Chromecast'),
                    'manufacturer': 'Google',
                    'model': 'Chromecast',
                    'ip': cast.get('ip'),
                    'port': cast.get('port', 8009),
                    'tv_type': 'chromecast',
                    'is_chromecast': True
                })
            
            print(f"  ✅ Chromecast: {len(devices)} encontrados")
            
        except Exception as e:
            print(f"  ⚠️  Erro na descoberta Chromecast: {e}")
        
        return devices

# ============== DESCOBERTA COMBINADA (DLNA + Chromecast) ==============

class CombinedDiscovery:
    def discover(self):
        """Descobre dispositivos DLNA e Chromecast"""
        all_devices = {}
        
        def discover_dlna_thread():
            print("  -> Buscando dispositivos DLNA...")
            discovery = DLNADiscovery()
            dlna_devs = discovery.discover()
            
            for dev in dlna_devs:
                if dev.get('ip'):
                    all_devices[dev['ip']] = dev
            
            print(f"  -- Encontrados {len(dlna_devs)} dispositivos DLNA.")
        
        def discover_chromecast_thread():
            print("  -> Buscando Chromecasts...")
            discovery = ChromecastDiscovery()
            cast_devs = discovery.discover()
            
            for dev in cast_devs:
                if dev.get('ip') and dev['ip'] not in all_devices:
                    all_devices[dev['ip']] = dev
            
            print(f"  -- Encontrados {len(cast_devs)} Chromecasts.")
        
        # Executa ambas as descobertas em threads separadas
        dlna_thread = threading.Thread(target=discover_dlna_thread)
        chromecast_thread = threading.Thread(target=discover_chromecast_thread)
        
        dlna_thread.start()
        chromecast_thread.start()
        
        dlna_thread.join()
        chromecast_thread.join()
        
        return list(all_devices.values())

# ============== CONTROLE DLNA ==============

class DLNAController:
    SOAP = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>{body}</s:Body>
</s:Envelope>"""
    
    NS = "urn:schemas-upnp-org:service:AVTransport:1"
    
    def __init__(self, control_url, tv_type='generic'):
        self.control_url = control_url
        self.tv_type = tv_type
    
    def _send(self, action, body):
        soap = self.SOAP.format(body=body)
        
        headers = {
            'Content-Type': 'text/xml; charset="utf-8"',
            'SOAPAction': f'"{self.NS}#{action}"',
            'User-Agent': 'DLNA-Streamer/1.0',
            'Connection': 'close',
        }
        
        try:
            req = urllib.request.Request(self.control_url, data=soap.encode(), headers=headers)
            resp = urllib.request.urlopen(req, timeout=TIMEOUT)
            return True, resp.read().decode('utf-8', errors='ignore')
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', errors='ignore') if e.fp else ''
            return False, f"HTTP {e.code}: {body}"
        except Exception as e:
            return False, str(e)
    
    def set_uri(self, uri, title="Stream"):
        mime = 'application/x-mpegURL' if '.m3u8' in uri.lower() else 'video/mp4'
        
        didl = f"""<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/">
<item id="0" parentID="-1" restricted="1">
<dc:title>{self._esc(title)}</dc:title>
<upnp:class>object.item.videoItem</upnp:class>
<res protocolInfo="http-get:*:{mime}:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">{self._esc(uri)}</res>
</item>
</DIDL-Lite>"""
        
        body = f"""<u:SetAVTransportURI xmlns:u="{self.NS}">
<InstanceID>0</InstanceID>
<CurrentURI>{self._esc(uri)}</CurrentURI>
<CurrentURIMetaData>{self._esc(didl)}</CurrentURIMetaData>
</u:SetAVTransportURI>"""
        
        return self._send("SetAVTransportURI", body)
    
    def set_uri_simple(self, uri):
        body = f"""<u:SetAVTransportURI xmlns:u="{self.NS}">
<InstanceID>0</InstanceID>
<CurrentURI>{self._esc(uri)}</CurrentURI>
<CurrentURIMetaData></CurrentURIMetaData>
</u:SetAVTransportURI>"""
        
        return self._send("SetAVTransportURI", body)
    
    def play(self):
        body = f"""<u:Play xmlns:u="{self.NS}">
<InstanceID>0</InstanceID>
<Speed>1</Speed>
</u:Play>"""
        return self._send("Play", body)
    
    def pause(self):
        body = f"""<u:Pause xmlns:u="{self.NS}">
<InstanceID>0</InstanceID>
</u:Pause>"""
        return self._send("Pause", body)
    
    def stop(self):
        body = f"""<u:Stop xmlns:u="{self.NS}">
<InstanceID>0</InstanceID>
</u:Stop>"""
        return self._send("Stop", body)
    
    def _esc(self, text):
        if not text:
            return ""
        return (str(text)
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&apos;'))

# ============== HANDLER DE REQUISIÇÕES PRINCIPAL ==============
def handle_request(client_socket, client_address, server_socket):
    """Processa requisição HTTP principal"""
    global LOCAL_IP, active_chromecast_controllers
    
    request_id = random_hex(8)
    print(f"[REQ-{request_id}] Nova conexão de {client_address[0]}:{client_address[1]}")
    
    http_client = SimpleHTTPClient(timeout=15)
    
    try:
        client_socket.settimeout(30)
        
        # Ler toda a requisição
        request_data = b''
        while True:
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            request_data += chunk
            if b'\r\n\r\n' in request_data:
                # Encontrou fim dos headers, agora ler body se existir
                headers_end = request_data.find(b'\r\n\r\n') + 4
                headers_part = request_data[:headers_end]
                
                # Verificar Content-Length
                headers_lines = headers_part.decode('utf-8', errors='ignore').split('\r\n')
                content_length = 0
                for line in headers_lines:
                    if line.lower().startswith('content-length:'):
                        content_length = int(line.split(':')[1].strip())
                        break
                
                # Se tem body, ler o restante
                if content_length > 0:
                    body_received = len(request_data) - headers_end
                    remaining = content_length - body_received
                    if remaining > 0:
                        request_data += client_socket.recv(remaining)
                break
        
        if not request_data:
            return
        
        request_text = request_data.decode('utf-8', errors='ignore')
        
        method, path, headers = parse_http_request(request_text)
        
        if not method or not path:
            return
        
        print(f"[REQ-{request_id}] {method} {path}")
        
        # Extrair body se for POST
        body_data = b''
        if method == 'POST':
            # Encontrar onde começa o body
            header_end = request_text.find('\r\n\r\n')
            if header_end != -1:
                body_start = header_end + 4
                if len(request_text) > body_start:
                    body_data = request_text[body_start:].encode('utf-8')
        
        if method != 'GET' and method != 'POST':
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
        proxy_host = f"{LOCAL_IP}:{PORT}"
        
        # ===== ROTA: / =====
        if path_part == "/":
            response_data = {
                "message": "ONEPLAY PROXY - QPython LAN Edition with DLNA + Chromecast",
                "status": "running",
                "local_ip": LOCAL_IP,
                "port": PORT,
                "dlna_proxy_port": PROXY_PORT,
                "chromecast_enabled": CHROMECAST_ENABLED,
                "endpoints": {
                    "app": f"http://{proxy_host}/app",
                    "oneplay": f"http://{proxy_host}/oneplay",
                    "hlsretry": f"http://{proxy_host}/hlsretry?url=<URL>",
                    "api_discover": f"http://{proxy_host}/api/discover"
                }
            }
            response = json.dumps(response_data, indent=2)
            client_socket.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
                response.encode('utf-8')
            )
        
        # ===== ROTA: /app =====
        elif path_part in ["/app", "/app/"]:            
            try:
                # Tenta buscar do GitHub
                r_html = http_client.request('https://raw.githack.com/zoreu/stream_roku/main/home_dlna_chromecast.html')
                
                if r_html.status_code == 200:
                    html = r_html.content.decode('utf-8', errors='ignore')
                    r_html.close()
                else:
                    # Fallback para HTML local
                    html = "<h1>OnePlay IPTV</h1><p>Proxy DLNA funcionando!</p>"

                # html = html.replace("{{PROXY_HOST}}", proxy_host)
                # with open('html_deep.html', 'r', encoding='utf-8') as f:
                #     html = f.read()

                client_socket.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" +
                    html.encode("utf-8")
                )
            except Exception as e:
                print(f"Erro ao fetch home.html: {e}")
                client_socket.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        
        # ===== ROTA: /oneplay =====
        elif path_part == "/oneplay":
            
            lista_param = query_params.get('lista', [None])[0]
            
            if lista_param and lista_param in ONEPLAY_LISTS:
                list_url = ONEPLAY_LISTS[lista_param]
            else:
                list_url = DEFAULT_ONEPLAY_LIST
            
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
        
        # ===== ROTA: /hlsretry =====
        elif path_part == "/hlsretry":
            
            url = query_params.get('url', [None])[0]
            if url:
                try:
                    url = unquote_plus(url)
                except:
                    pass
                url = convert_to_m3u8(url)
            
            if not url:
                client_socket.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\nNo URL provided")
                return
            
            try:
                req_headers = {k: v for k, v in headers.items() if k.lower() != 'host'}
                response = http_client.request(url, headers=req_headers, stream=False)
                
                if response.status_code == 200:
                    content_type = response.headers.get("Content-Type", "").lower()
                    
                    if "mpegurl" in content_type or ".m3u8" in url.lower():
                        base_url = url.rsplit('/', 1)[0]
                        playlist_content = response.content.decode('utf-8', errors='ignore')
                        rewritten = rewrite_m3u8_urls(playlist_content, base_url, 'http', proxy_host)
                        client_socket.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/vnd.apple.mpegurl\r\n\r\n" +
                            rewritten.encode('utf-8')
                        )
                        response.close()
                        return
                    
                    # Stream binário
                    media_type = (
                        'video/mp4' if '.mp4' in url.lower()
                        else 'video/mp2t' if '.ts' in url.lower() or '/hl' in url.lower()
                        else response.headers.get("Content-Type", "application/octet-stream")
                    )
                    
                    response_headers = {
                        k: v for k, v in response.headers.items()
                        if k.lower() in ['content-type', 'accept-ranges', 'content-range', 'content-length']
                    }
                    
                    header_str = f"HTTP/1.1 200 OK\r\n"
                    for k, v in response_headers.items():
                        header_str += f"{k}: {v}\r\n"
                    header_str += f"Content-Type: {media_type}\r\n\r\n"
                    
                    client_socket.sendall(header_str.encode('utf-8'))
                    client_socket.sendall(response.content)
                    response.close()
                    return
                
                else:
                    response.close()
                    client_socket.sendall(f"HTTP/1.1 {response.status_code} Error\r\n\r\n".encode())
                    
            except Exception as e:
                print(f"[REQ-{request_id}] Erro no hlsretry: {e}")
                error_response = json.dumps({
                    "error": "Failed to fetch stream",
                    "message": str(e),
                    "request_id": request_id
                })
                client_socket.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\n\r\n" +
                    error_response.encode('utf-8')
                )
        
        # ===== API DE DESCOBERTA (DLNA + Chromecast) =====
        elif path_part == "/api/discover":
            print("\n🔍 Buscando dispositivos DLNA e Chromecast...")
            discovery = CombinedDiscovery()
            devs = discovery.discover()
            print(f"✅ {len(devs)} dispositivos encontrados\n")
            
            response_data = {
                'success': True,
                'devices': [{
                    'id': d.get('id', d.get('ip')),
                    'name': d.get('name', 'Dispositivo Desconhecido'),
                    'manufacturer': d.get('manufacturer', ''),
                    'model': d.get('model', ''),
                    'ip': d.get('ip'),
                    'port': d.get('port', 8009 if d.get('tv_type') == 'chromecast' else None),
                    'control_url': d.get('control_url'),
                    'tv_type': d.get('tv_type', 'generic'),
                    'is_chromecast': d.get('tv_type') == 'chromecast' or d.get('is_chromecast', False)
                } for d in devs]
            }
            response = json.dumps(response_data)
            client_socket.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Access-Control-Allow-Origin: *\r\n"
                b"\r\n" + response.encode('utf-8')
            )
        
        # ===== API DE TRANSMISSÃO (DLNA + Chromecast) =====
        elif path_part == "/api/cast" and method == 'POST':
            print(f"[REQ-{request_id}] Rota: /api/cast (POST)")
            
            try:
                if not body_data:
                    print("❌ Body vazio")
                    client_socket.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\nEmpty body")
                    return
                
                # Parse JSON
                data = json.loads(body_data.decode('utf-8'))
                print(f"✅ JSON parseado: {data}")
                
                url = data.get('url', '')
                tv_type = data.get('tv_type', 'generic')
                device_name = data.get('device_name', 'TV')
                ip = data.get('ip')
                port = data.get('port')
                control_url = data.get('control_url')
                
                if not url:
                    print("❌ URL faltando")
                    client_socket.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\nMissing url")
                    return
                
                print(f"📡 Transmitindo para: {device_name} ({tv_type})")
                print(f"   URL Original: {url}")
                print(f"   Tipo TV: {tv_type}")
                
                with active_sessions_lock:
                    # LÓGICA PARA CHROMECAST
                    if 'chromecast' in tv_type:
                        if not CHROMECAST_ENABLED:
                            error_msg = "Módulo Chromecast não está carregado."
                            print(f"❌ {error_msg}")
                            response_data = {'success': False, 'error': error_msg}
                            client_socket.sendall(
                                b"HTTP/1.1 400 Bad Request\r\n"
                                b"Content-Type: application/json\r\n\r\n" +
                                json.dumps(response_data).encode()
                            )
                            return
                        
                        if not ip:
                            error_msg = "IP do Chromecast é obrigatório."
                            print(f"❌ {error_msg}")
                            response_data = {'success': False, 'error': error_msg}
                            client_socket.sendall(
                                b"HTTP/1.1 400 Bad Request\r\n"
                                b"Content-Type: application/json\r\n\r\n" +
                                json.dumps(response_data).encode()
                            )
                            return
                        
                        print(f"   📺 Chromecast: {device_name} ({ip}:{port})")
                        
                        # Desconecta qualquer sessão anterior neste IP
                        if ip in active_chromecast_controllers:
                            try:
                                active_chromecast_controllers[ip].disconnect()
                            except:
                                pass
                            del active_chromecast_controllers[ip]
                        
                        # Cria controlador Chromecast
                        try:
                            #cc = chromecast_support.ChromecastController(ip, port or 8009)
                            cc = ChromecastController(ip, port or 8009)
                            
                            # Inicia app de mídia
                            if cc.launch_app():
                                print("   ✅ App de mídia iniciado. Carregando stream...")
                                cc.load_media(url, title=device_name)
                                active_chromecast_controllers[ip] = cc
                                
                                response_data = {
                                    'success': True,
                                    'message': f"Transmitindo para {device_name} (Chromecast)",
                                    'stream_id': f"chromecast_{ip}"
                                }
                            else:
                                error_msg = "Não foi possível iniciar o app de mídia no Chromecast."
                                print(f"❌ {error_msg}")
                                response_data = {'success': False, 'error': error_msg}
                        except Exception as e:
                            error_msg = f"Erro ao conectar ao Chromecast: {str(e)}"
                            print(f"❌ {error_msg}")
                            response_data = {'success': False, 'error': error_msg}
                    
                    # LÓGICA PARA DLNA
                    else:
                        if not control_url:
                            error_msg = "Control URL é obrigatório para DLNA."
                            print(f"❌ {error_msg}")
                            response_data = {'success': False, 'error': error_msg}
                            client_socket.sendall(
                                b"HTTP/1.1 400 Bad Request\r\n"
                                b"Content-Type: application/json\r\n\r\n" +
                                json.dumps(response_data).encode()
                            )
                            return
                        
                        print(f"   📺 DLNA: {device_name}")
                        
                        # Gera ID único para o stream
                        stream_id = hashlib.md5(f"{url}{time.time()}".encode()).hexdigest()[:12]
                        
                        # Salva informações do stream
                        active_streams[stream_id] = {
                            'url': url,
                            'base_url': url.rsplit('/', 1)[0] + '/' if '/' in url else url + '/',
                            'created': time.time(),
                            'device_name': device_name
                        }
                        
                        print(f"   Stream ID: {stream_id}")
                        
                        # URL do proxy deve terminar com barra para LG WebOS
                        proxy_url = f"http://{LOCAL_IP}:{PROXY_PORT}/stream/{stream_id}/"
                        print(f"   URL Proxy: {proxy_url}")
                        
                        # Cria controlador DLNA
                        controller = DLNAController(control_url, tv_type)
                        
                        # Tenta enviar para a TV
                        print("   📤 Enviando SetAVTransportURI...")
                        success, result = controller.set_uri(proxy_url, title=f"Stream {stream_id}")
                        
                        if not success:
                            print(f"   ⚠️ SetURI falhou, tentando modo simplificado...")
                            success, result = controller.set_uri_simple(proxy_url)
                        
                        if not success:
                            print(f"   ❌ Falha ao enviar para a TV: {result}")
                            # Remove stream se falhou
                            if stream_id in active_streams:
                                del active_streams[stream_id]
                            
                            error_msg = str(result)
                            if '716' in error_msg or 'timed out' in error_msg.lower():
                                error_msg = f"A TV não consegue acessar o proxy. Verifique: 1) TV e proxy na mesma rede, 2) Firewall permitindo porta {PROXY_PORT}, 3) A TV pode acessar {LOCAL_IP}:{PROXY_PORT}"
                            
                            response_data = {'success': False, 'error': error_msg}
                            client_socket.sendall(
                                b"HTTP/1.1 400 Bad Request\r\n"
                                b"Content-Type: application/json\r\n\r\n" +
                                json.dumps(response_data).encode()
                            )
                            return
                        
                        # Aguarda um pouco e envia Play
                        time.sleep(0.5)
                        print("   ▶️ Enviando comando Play...")
                        play_success, play_result = controller.play()
                        
                        if not play_success:
                            print(f"   ⚠️ Play falhou: {play_result}")
                        
                        print(f"   ✅ Transmissão iniciada com sucesso!")
                        
                        response_data = {
                            'success': True, 
                            'stream_id': stream_id,
                            'proxy_url': proxy_url,
                            'message': f"Stream enviado para {device_name}"
                        }
                
                # Retorna resposta
                response = json.dumps(response_data)
                client_socket.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Access-Control-Allow-Origin: *\r\n"
                    b"\r\n" + response.encode('utf-8')
                )
                
            except json.JSONDecodeError as e:
                print(f"❌ Erro ao decodificar JSON: {e}")
                print(f"Body recebido: {body_data.decode('utf-8', errors='ignore')}")
                client_socket.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid JSON")
            except Exception as e:
                print(f"❌ Erro em /api/cast: {e}")
                traceback.print_exc()
                client_socket.sendall(f"HTTP/1.1 500 Internal Server Error\r\n\r\n{str(e)}".encode())
        
        # ===== API DE CONTROLE (DLNA + Chromecast) =====
        elif path_part == "/api/control" and method == 'POST':
            try:
                if not body_data:
                    client_socket.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    return
                
                data = json.loads(body_data.decode('utf-8'))
                action = data.get('action', '')
                tv_type = data.get('tv_type', 'generic')
                ip = data.get('ip')
                control_url = data.get('control_url')
                
                if not action:
                    client_socket.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    return
                
                print(f"Controle: {action} (Tipo: {tv_type})")
                
                with active_sessions_lock:
                    # CONTROLE CHROMECAST
                    if 'chromecast' in tv_type:
                        if ip and ip in active_chromecast_controllers:
                            cc = active_chromecast_controllers[ip]
                            print(f"   🎮 Chromecast ({ip}): {action}")
                            
                            if action == 'play':
                                cc.play()
                            elif action == 'pause':
                                cc.pause()
                            elif action == 'stop':
                                cc.stop()
                                cc.disconnect()
                                del active_chromecast_controllers[ip]
                        else:
                            print(f"   ⚠️ Chromecast {ip} não encontrado")
                    
                    # CONTROLE DLNA
                    else:
                        if control_url:
                            print(f"   🎮 DLNA: {action}")
                            ctrl = DLNAController(control_url)
                            
                            if action == 'play':
                                ctrl.play()
                            elif action == 'pause':
                                ctrl.pause()
                            elif action == 'stop':
                                ctrl.stop()
                        else:
                            print(f"   ⚠️ Control URL não fornecido para DLNA")
                
                response = json.dumps({'success': True})
                client_socket.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Access-Control-Allow-Origin: *\r\n"
                    b"\r\n" + response.encode('utf-8')
                )
                
            except Exception as e:
                print(f"Erro em /api/control: {e}")
                client_socket.sendall(b"HTTP/1.1 500 Internal Server Error\r\n\r\n")
        
        # ===== API DE PARAR STREAM =====
        elif path_part == "/api/stop-stream" and method == 'POST':
            try:
                if not body_data:
                    client_socket.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    return
                
                data = json.loads(body_data.decode('utf-8'))
                sid = data.get('stream_id', '')
                
                print(f"Parando stream: {sid}")
                if sid in active_streams:
                    del active_streams[sid]
                    print(f"Stream {sid} removido")
                else:
                    print(f"Stream {sid} não encontrado")
                
                response = json.dumps({'success': True})
                client_socket.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Access-Control-Allow-Origin: *\r\n"
                    b"\r\n" + response.encode('utf-8')
                )
                
            except Exception as e:
                print(f"Erro em /api/stop-stream: {e}")
                client_socket.sendall(b"HTTP/1.1 500 Internal Server Error\r\n\r\n")
        
        # ===== ROTA: /player =====
        elif path_part == "/player":
            url_param = query_params.get('url', [None])[0]
            
            if url_param:
                try:
                    url_param = unquote_plus(url_param)
                except:
                    pass
                
                # HTML do player
                html = f"""<!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>Player HLS</title>
                    <script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
                </head>
                <body>
                    <h1>Player HLS</h1>
                    <video id="video" controls width="100%"></video>
                    <script>
                        const video = document.getElementById('video');
                        const url = "{url_param}";
                        
                        if (Hls.isSupported()) {{
                            const hls = new Hls();
                            hls.loadSource(url);
                            hls.attachMedia(video);
                            hls.on(Hls.Events.MANIFEST_PARSED, function() {{
                                video.play();
                            }});
                        }} else if (video.canPlayType('application/vnd.apple.mpegurl')) {{
                            video.src = url;
                            video.addEventListener('loadedmetadata', function() {{
                                video.play();
                            }});
                        }}
                    </script>
                </body>
                </html>"""
                
                client_socket.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" +
                    html.encode('utf-8')
                )
            else:
                html = f"""
                <html>
                <head><title>Player</title></head>
                <body>
                    <h1>Player HLS</h1>
                    <form method="GET">
                        <input type="text" name="url" placeholder="URL M3U8" size="80">
                        <button type="submit">Play</button>
                    </form>
                    <p>Exemplo: http://{proxy_host}/player?url=http://exemplo.com/stream.m3u8</p>
                </body>
                </html>
                """
                client_socket.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
                    html.encode()
                )
        
        # ===== ROTA NÃO ENCONTRADA =====
        else:
            client_socket.sendall(b"HTTP/1.1 404 Not Found\r\n\r\nNot Found")
    
    except socket.timeout:
        pass
    except Exception as e:
        print(f"[REQ-{request_id}] Erro: {e}")
        traceback.print_exc()
    finally:
        try:
            client_socket.close()
        except:
            pass

# ============== SERVIDOR ==============
def start_proxy():
    """Inicia o servidor proxy"""
    global SHUTDOWN_EVENT, LOCAL_IP
    
    print("\n🚀 Iniciando proxy...")
    
    LOCAL_IP = get_local_ip()
    print(f"📍 IP Local detectado: {LOCAL_IP}")
    
    if CHROMECAST_ENABLED:
        print("✅ Chromecast: Habilitado")
    else:
        print("⚠️  Chromecast: Desabilitado (módulo não encontrado)")
    
    # Iniciar DLNA proxy
    print("🚀 Iniciando DLNA proxy...")
    dlna_proxy_thread = threading.Thread(target=start_dlna_proxy_server, daemon=True)
    dlna_proxy_thread.start()
    dlna_proxy_ready.wait(timeout=5)
    time.sleep(0.5)
    
    # Testar DLNA proxy
    if test_port_open("127.0.0.1", PROXY_PORT):
        print(f"   ✅ DLNA Proxy OK")
    else:
        print(f"   ❌ DLNA Proxy falhou!")
    
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
    
    print(f"\n🌐 Acesse: http://{LOCAL_IP}:{PORT}/app")
    print(f"📺 DLNA Proxy: http://{LOCAL_IP}:{PROXY_PORT}")
    print(f"🔍 Chromecast: {'Suportado' if CHROMECAST_ENABLED else 'Não suportado'}")
    print(f"\n⌨️  Pressione Ctrl+C para parar o servidor\n")
    
    try:
        while not SHUTDOWN_EVENT.is_set():
            try:
                client_socket, client_address = server_socket.accept()
                thread = threading.Thread(
                    target=handle_request,
                    args=(client_socket, client_address, server_socket),
                    name=f"Handler-{client_address[0]}"
                )
                thread.daemon = True
                thread.start()
            except socket.timeout:
                continue
            except socket.error as e:
                if not SHUTDOWN_EVENT.is_set():
                    print(f"Erro ao aceitar conexão: {e}")
    
    except KeyboardInterrupt:
        print("\n\n⏹️  Interrupção detectada (Ctrl+C)")
        print("🛑 Encerrando servidor proxy...")
    
    finally:
        SHUTDOWN_EVENT.set()
        server_socket.close()
        print("✅ Servidor proxy encerrado com sucesso!\n")
    
    return True

# ============== MAIN ==============
if __name__ == '__main__':
    start_proxy()
