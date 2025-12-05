# DLNA + ONEPLAY
stream nas tvs ROKU/LG/SANSUNG/PHILIPS/TCL/PHILCO

Tutorial:

1 - baixe o qpython ou pydroid 3 no celular

2 - vá em configurações, app, escolha o app que baixou e em bateria deixa como não restrito pra pode ficar rodando em segundo plano

3 - copie o codigo abaixo

```python
import urllib.request

url = 'https://raw.githack.com/zoreu/stream_roku/main/dlna_completo.py'
response = urllib.request.urlopen(url)
code = response.read().decode('utf-8')
exec(code)
```

PARA QPYTHON:

 - no qpython clique em Editor e cole o codigo

 - salve e dê o nome oneplay.py

 - clique no play para rodar o proxy

 - no log do qpython decore o endereço do proxy como http://192.168.0.2:8094/app e minimize pra ficar rodando em segundo plano

 - no navegador do celular abra a url como: http://192.168.0.2:8094/app (altere o ip para o do seu celular)

 - abra um canal e clique em espelhar para tv, escolha seu dispositivo e pronto

PARA PYDROID 3:

 - abra o pydroid 3, ignore algum anuncio e coloque suas preferencias que ele pedir caso peça
  
 - copie o codigo abaixo:

```python
import urllib.request

url = 'https://raw.githack.com/zoreu/stream_roku/main/dlna_completo.py'
response = urllib.request.urlopen(url)
code = response.read().decode('utf-8')
exec(code)
```
- cole o codigo no pydroid 3
  
- clique na pasta, depois save as, escolha internal storage depois download, logo em baixo dê o nome de oneplay.py e clique em save

- agora basta clicar no play pra executar o codigo

- no navegador do celular abra a url como: http://192.168.0.2:8094/app (altere o ip para o do seu celular)

- abra um canal e clique em espelhar para tv, escolha seu dispositivo e pronto

obs: sempre que abrir o pydroid 3 clique na pasta e clique em open, depois internal storage, download e escolha o script oneplay.py que salvou e agora pode executar o script



