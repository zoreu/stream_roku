# stream_roku
stream roku

```python
import urllib.request
url = 'https://cdn.jsdelivr.net/gh/zoreu/stream_roku/proxy.py'
response = urllib.request.urlopen(url)
code = response.read().decode('utf-8')
exec(code)
```
