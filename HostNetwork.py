# -*- coding: utf-8 -*
import netifaces
import socket


def HostNetwork():

    ip_iface = []  # 本机全部ip地址和网卡地址
    IfaceName = "" # 本机正在用的ip地址对应的网卡地址
    mac = ""
    rou = ""  # 网关地址

    try:
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sk.connect(('8.8.8.8', 80))
        ip = sk.getsockname()[0]
    finally:
        sk.close()

    # 获取本机的全部ip地址和网卡名称的列表
    for Name in netifaces.interfaces():
        ip_iface += [[i['addr'], Name] for i in netifaces.ifaddresses(Name).setdefault(netifaces.AF_INET, [{'addr': 'No IP addr'}])]

    # 本机正在用的ip地址对应的网卡地址
    for tt in ip_iface:
        if tt[0] == ip:
            IfaceName = tt[1]

    # 获取mac
    mac = netifaces.ifaddresses(IfaceName)[netifaces.AF_LINK][0]['addr']

    # 获取网关地址
    for k in netifaces.gateways().get(netifaces.AF_INET):
        if k[1] == IfaceName:
            rou = k[0]
    return [ip, rou, mac]


if __name__ == "__main__":

    hostnetwork = HostNetwork()
    print(hostnetwork)