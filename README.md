# portscan
一个基于Python+Go的端口扫描及服务探测脚本


# 0x00 前言

近期由于公司环境整改/迭代以及历史弱口令等撞库，运维同事将内网测试环境的一些SSH等敏感端口对外，导致被挖矿团伙利用进行挖矿，虽然生产环境存在物理隔离，但仍存在极大安全风险，对此需要对所有用户进行端口对外开放监控。

# 0x01 确定方案

通过网上调研，发现滴滴安全应急响应中心发过一个相关的文章![](http://blog.w2n1ck.com/didisrc.png)

需求基本一致，使用了下文章中提到的代码进行测试，可能我环境/带宽/目标等多种因素，导致测试之后发现并不理想，扫描速度慢且有时不稳定。

经过github、sourceforge、stackoverflow等一番搜索及疯狂复制粘贴，完成了个勉强算的上的成品。

代码逻辑如下：

![](http://blog.w2n1ck.com/portscan-jiagou.png)



## 1.1 用户输入目标处理

```shell
# 单独IP/HOST
ip: 127.0.0.1
ip_list: 127.0.0.1

# CIDR
ip: 127.0.0
ip_list: 127.0.0.1, 127.0.0.2, 127.0.0.3 ... 127.0.0.254

# IP访问
ip: 127.0.0.1-127.0.0.20
ip_list: 127.0.0.1, 127.0.0.2, 127.0.0.3 ... 127.0.0.20

# 文件
ip: ip.txt
ip_list: Same as above
```

## 1.2 目标存活探测

使用ICMP协议进行ping检测，使用的第三方库pyping（该库不支持python3，若要用py3需要自己转换下）

## 1.3 Go脚本探测

编译`port_scan.go`

```shell
go build -buildmode=c-shared -o portscan.so portscan.go
```

探测结果返回：

```
# 单个端口
94.191.42.58:22
# 多个端口
94.191.42.58:22, 9099
```

## 1.4 nmap指纹识别

根据go探测结果进行解析，分别使用nmap库进行服务识别

```bash
pip install python-nmap
```

返回结果：

```shell
127.0.0.1:22/ssh
127.0.0.1:9999:unknown
...
```

## 1.5 web service

若nmap结果返回为`http`，`unknown`，`sun-answerbook`等时，尝试连接获取title

# 0x02 代码实现

## 2.1 用户输入处理

```python
def get_ip_list(ip):
    '''
    ip: 127.0.0.1
    ip_list: 127.0.0.1

    ip: 127.0.0
    ip_list: 127.0.0.1, 127.0.0.2, 127.0.0.3 ... 127.0.0.254

    ip: 127.0.0.1-127.0.0.20
    ip_list: 127.0.0.1, 127.0.0.2, 127.0.0.3 ... 127.0.0.20

    ip: ip.txt
    ip_list: Same as above
    '''
    ip_list = []
    iptonum = lambda x:sum([256**j*int(i) for j,i in enumerate(x.split('.')[::-1])])
    numtoip = lambda x: '.'.join([str(x/(256**i)%256) for i in range(3,-1,-1)])

    pattern = re.compile(
        r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
        r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
        )

    if '-' in ip:
        ip_range = ip.split('-')
        ip_start = long(iptonum(ip_range[0]))
        ip_end = long(iptonum(ip_range[1]))
        ip_count = ip_end - ip_start
        # print(ip_range,ip_start, ip_end, ip_count)
        if ip_count >= 0 and ip_count <= 65536:
            for ip_num in range(ip_start,ip_end+1):
                ip_list.append(numtoip(ip_num))
        else:
            print('wrong format')
    elif '.txt' in ip:
        ip_file = open(ip, 'r')
        for ip in ip_file:
            ip_list.extend(get_ip_list(ip.strip()))
        ip_file.close()
    elif pattern.match(ip):
        ip_list.append(ip)
    else:
        ip_split=ip.split('.')
        net = len(ip_split)
        if net == 2:
            for b in range(1,255):
                for c in range(1,255):
                    ip = "%s.%s.%d.%d"%(ip_split[0],ip_split[1],b,c)
                    ip_list.append(ip)
        elif net == 3:
            for c in range(1,255):
                ip = "%s.%s.%s.%d"%(ip_split[0],ip_split[1],ip_split[2],c)
                ip_list.append(ip)
        elif net ==4:
            ip_list.append(ip)
        else:
            print('wrong format')
    return ip_list
```

## 2.2 目标存活探测

```python
def get_target_status(target):
    try:
        r = pyping.ping(target)
        if r.ret_code == 0:
            return True
        else:
            return False
    except:
        return False
```

## 2.3 Go脚本探测

```python

lib = cdll.LoadLibrary(u'./portscan.so')
lib.Scan.argtypes = [c_char_p]
lib.Scan.restype = c_char_p

def run(ip):
    if get_target_status(ip):
        print("\033[32m[ * ] {} is alive\033[0m".format(ip))
        ip = str(ip).encode("utf-8")
        temp_result = str(lib.Scan(ip))
        print('\033[33mScan Result:{}\033[0m'.format(temp_result))
        if ',' in temp_result:
            port_list = temp_result.split(':')[1].split(',')
            # print(port_list)
            port_num = len(port_list)
            if port_num > 30:
                print('Possible WAF/CND on target.')
            else:
                for i in range(len(port_list)):
                    port = str(port_list[i]).strip()
                    # print(port, int(port))
                    nmap_scan(ip=ip, port=int(port), arg="-sS -Pn --version-all --open -p")
        else:
            port_list = temp_result.split(':')[1]
            # print(port_list)
            nmap_scan(ip=ip,port=port_list,arg="-sS -Pn --version-all -p")
    else:
        print("\033[31m[ * ] {} is not alive\033[0m".format(ip))
```

## 1.4 nmap指纹识别

```python
nm =nmap.PortScanner()
def nmap_scan(ip,port,arg):
    try:
        ret = nm.scan(ip, arguments=arg+str(port))
        # print(ret)
        service_name = ret['scan'][ip]['tcp'][int(port)]['name']
        
        if 'http' in service_name  or service_name == 'sun-answerbook' or 'unknown' in service_name:
            if service_name == 'https' or service_name == 'https-alt':
                scan_url = 'https://{}:{}'.format(ip,port)
                title = get_title(scan_url)
                service_name = '{}(title:{})'.format(service_name,title)
            else:
                scan_url = 'http://{}:{}'.format(ip,port)
                title = get_title(scan_url)
                service_name = '{}(title:{})'.format(service_name,title)
        
        print('\033[32m[ * ] {}:{}/{}\033[0m'.format(ip, port, service_name))

    except nmap.nmap.PortScannerError:
        print("Please run -O method for root privileges")
```

## 1.5 web service

```python
def get_title(scan_url):
    try:
        r = requests.get(scan_url,timeout=5, verify=False)
        r_detectencode = chardet.detect(r.content)
        # print(r_detectencode)
        actual_encode = r_detectencode['encoding']
        response = re.findall(u'<title>(.*?)</title>', r.content, re.S)
        # print(response)
        if response == []:
            return None
        else:
            title = response[0].decode(actual_encode).decode('utf-8')
            # banner = r.headers['server']
            return title
    except Exception as e:
        pass
```

# 0x03 运行效果

以tx云的一台vps为例，全端口扫描+服务识别我测试的稳定在40s之内，还可以。但是有些IP不知什么情况会比较慢，还需进行优化。

![](http://blog.w2n1ck.com/portscan-result.png)

go代码就不放了，太烂了，完全cv拼凑的，若有兴趣可私聊讨论。

### 参考文章

https://medium.com/@KentGruber/building-a-high-performance-port-scanner-with-golang-9976181ec39d

https://github.com/golang/go/blob/master/src/cmd/cgo/doc.go

https://www.coder.work/article/202337

https://www.kancloud.cn/kancloud/web-application-with-golang/

https://www.yuyang.io/post/python-go-dynamic/

https://ejin66.github.io/2018/09/15/go-to-so-android.html

https://github.com/tkuebler/pyping

https://ixyzero.com/blog/archives/4171.html

![](http://blog.w2n1ck.com/w2n1ck-code.gif)


