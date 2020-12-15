# 修改记录日志

## 2020/12/11

1.建立虚拟环境Flask_SocketIO包不适配问题，
```
解决办法：先注释requirements中Flask_SocketIO包指定版本安装默认版本，之后再安装4.1.0
```

2.环境包配置后运行报错
File "E:\Task\satallite\venv\lib\site-packages\engineio\client.py", line 2, in module from json import JSONDecodeError,
ImportError: cannot import name JSONDecodeError
```
解决办法：虚拟环境中pip install simplejson,配置 E:\Task\satallite\venv\lib\site-packages\engineio\client.py
from json import JSONDecodeError 中的json改为 simplejson
```
3.venv虚拟环境压缩后*venv.7z*(路径:mydata\venv.7z)上传git，文件夹依旧不同步