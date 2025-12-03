# DLNA ROKU + ONEPLAY
stream roku

Tutorial:

1 - baixe o web video cast na tv roku e no celular android

2 - baixe o qpython 3L no celular android

3 - copie o codigo abaixo

```python
import urllib.request

url = 'https://raw.githack.com/zoreu/stream_roku/main/proxy.py'
response = urllib.request.urlopen(url)
code = response.read().decode('utf-8')
exec(code)
```
4 - no qpython clique em Editor e cole o codigo

5 - salve e dê o nome oneplay.py

6 - clique no play para rodar o proxy

7 - no log do qpython decore o endereço do proxy em LISTA IPTV algo como http://192.168.0.2:8094/oneplay e minimize pra ficar rodando em segundo plano

8 - no web video cast do celular clique nas lista de opções e clique em IPTV

9 - clique no + e adicione a lista que você decorou algo como http://192.168.0.2:8094/oneplay

10 - dê o nome de oneplay e clique em salvar

11 - abra um canal e coloque pra espelhar pra tv roku

# NOVIDADE

com a mais recente atualização é possivel usar a rota /app no navegador do web video cast pra mais praticidade

exemplo: http://192.168.0.2:8094/app se quiser pode adicionar esse endereço na sua tv

OBS: de prefência conecte o celular no carregador pra não descarregar
