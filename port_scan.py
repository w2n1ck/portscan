#! _*_ coding:utf-8 _*_
import re
import time
import requests
import chardet
from ctypes import cdll, c_char_p
import pyping
import nmap

'''
pip install python-nmap
pip install pyping
'''

lib = cdll.LoadLibrary(u'./portscan.so')
lib.Scan.argtypes = [c_char_p]
lib.Scan.restype = c_char_p

# ip = "94.191.42.63".encode("utf-8")
# rs = lib.Scan(ip)
# print('Scan Result: ',rs)

def get_target_status(target):
    try:
        r = pyping.ping(target)
        if r.ret_code == 0:
            return True
        else:
            return False
    except:
        return False


nm =nmap.PortScanner()
def nmap_scan(ip,port,arg):
    try:
        ret = nm.scan(ip, arguments=arg+str(port))
        # print(ret)
        service_name = ret['scan'][ip]['tcp'][int(port)]['name']
        print(ip,port,service_name)
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
        return '{}:{}/{}'.format(ip, port, service_name)

    except nmap.nmap.PortScannerError:
        print("Please run -O method for root privileges")


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

_ip = '94.191.42.{}'

# temp_result = 'Scan Result:94.191.42.58:22, 9099'

result = open('./temp_result.txt', 'a')

def run(ip):
    if get_target_status(ip):
        print("\033[32m[ * ] {} is alive\033[0m".format(ip))
        ip = str(ip).encode("utf-8")
        temp_result = str(lib.Scan(ip))
        print('\033[33mScan Result:{}\033[0m'.format(temp_result))
        if '(' in temp_result:
            ip = temp_result.split('(')[0].strip()
            host = temp_result.split('(')[1].split(')')[0]
            print('Get host: {} ip:{}'.format(host,ip))
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
                    scan_result = nmap_scan(ip=ip, port=int(port), arg="-sS -Pn --version-all --open -p")

        else:
            port_list = temp_result.split(':')[1]
            # print(port_list)
            scan_result = nmap_scan(ip=ip,port=port_list,arg="-sS -Pn --version-all -p")
        if host:
            result.write(scan_result + '-{}\n'.format(host))
        else:
            result.write(scan_result + '\n')
    else:
        print("\033[31m[ * ] {} is not alive\033[0m".format(ip))


def is_ip(ip):
    compile_rule = re.compile(r'\d+[\.]\d+[\.]\d+[\.]\d+')
    match_list = re.findall(compile_rule, ip)
    if match_list:
        return True
    else:
        return False

def get_ip_list(ip):
    '''
    ip: 127.0.0.1
    ip_list: 127.0.0.1

    ip: 127.0.0
    ip_list: 127.0.0.1, 127.0.0.2, 127.0.0.3 ... 127.0.0.254

    ip: 127.0.0.1/127.0.0.20
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
    if not is_ip(ip):
        ip_list.append(ip)
    else:
        if '-' in ip:
            ip_range = ip.split('/')
            ip_start = long(iptonum(ip_range[0]))
            ip_end = long(iptonum(ip_range[1]))
            ip_count = ip_end - ip_start
            # print(ip_range,ip_start, ip_end, ip_count)
            if ip_count >= 0 and ip_count <= 65536:
                for ip_num in range(ip_start,ip_end+1):
                    ip_list.append(numtoip(ip_num))
            else:
                print('{} wrong format'.format(ip))
        elif '.txt' in ip:
            ip_file = open(ip, 'r')
            for ip in ip_file:
                ip_list.extend(get_ip_list(ip.strip()))
            ip_file.close()
        # elif pattern.match(ip):
        #     ip_list.append(ip)
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
                print('{} wrong format'.format(ip))
    return ip_list


if __name__ == "__main__":
    s_time = time.time()
    ip_file = open('./ip.txt', 'r')
    ip_list = list()
    for _ in ip_file.readlines():
        _ip_list = get_ip_list(_.strip())
        ip_list = ip_list + _ip_list
    # print(ip_list)
    ip_file.close()
    for i in range(len(ip_list)):
        print(ip_list[i])
        run(ip_list[i])
    e_time = time.time()
    print("\033[32m[ * ] Scan All Time is {}.\033[0m".format(e_time-s_time))
    result.close()
