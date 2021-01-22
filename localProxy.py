'''
Copyright (c)2020, by Qogir, JMJ, MA71
All rights reserved.    
File Name: LocalProxy       
System Name: SwiftProxy
Date: 2020-12-01
Version: 1.0
Description: 本地代理服务器。该模块主要依赖asyncio和websockets库，并使用协程/单线程异步IO的思想进行编程，是本程序的核心模块.
'''

import argparse
import asyncio
import ipaddress
import json
import logging
import signal
import struct
import sys
import traceback
import websockets

from enum import Enum
ReadMode = Enum('ReadMod', ('EXACT', 'LINE', 'MAX', 'UNTIL'))   # 对应四种读模式

class MyError(Exception):   # 自定义一个异常类，raise抛出错误实例，便于追踪
    pass

gSendByteCount = 0  # 全局变量，记录数据流量用
gSendBandwidth = 0
gRecvByteCount = 0
gRecvBandwidth = 0


async def aioClose(w, *, logHint=None): # 关闭对应服务器，输出log信息
    if not w:
        await asyncio.sleep(0.001)
        return
    host, port, *_ = w.get_extra_info('peername')
    log.info(f'{logHint} close {host} {port}')
    try:
        w.close()
        await w.wait_closed()
    except Exception as exc:
        pass


async def aioRead(r, mode, *, logHint=None, exactData=None, exactLen=None, maxLen=-1, untilSep=b'\r\n'):    # 读报文，有四种模式
    data = None     
    try:
        if ReadMode.EXACT == mode:      # 读精确的几字节
            exactLen = len(exactData) if exactData else exactLen
            data = await r.readexactly(exactLen)
            if exactData and data != exactData:
                raise MyError(f'recvERR={data} {logHint}')
        elif ReadMode.LINE == mode:     # 读一行
            data = await r.readline()
        elif ReadMode.MAX == mode:      # 读大量字节，长度为maxLen
            data = await r.read(maxLen)
        elif ReadMode.UNTIL == mode:    # 读到对应分隔符
            data = await r.readuntil(untilSep)
        else:
            log.error(f'INVALID mode={mode}')
            exit(1)
    except asyncio.IncompleteReadError as exc:
        raise MyError(f'recvEXC={exc} {logHint}')
    except ConnectionAbortedError as exc:
        raise MyError(f'recvEXC={exc} {logHint}')
    except ConnectionResetError as exc:
        raise MyError(f'recvEXC={exc} {logHint}')
    if not data:
        raise MyError(f'EOF {logHint}')
    return data

async def aioWrite(w, data, *, logHint=''):     # 写报文
    try:
        w.write(data)
        await w.drain()     # 与write配套，用于立即清空缓冲区
    except ConnectionAbortedError as exc:
        raise MyError(f'sendEXC={exc} {logHint}')
    except ConnectionResetError as exc:
        raise MyError(f'recvEXC={exc} {logHint}')

async def socks5ReadDstHost(r, atyp, *, logHint):   # 读取不同种类的主机地址
    dstHost = None
    if atyp == b'\x01':
        dstHost = await aioRead(r, ReadMode.EXACT, exactLen=4, logHint=f'{logHint} ipv4')   # ipv4
        dstHost = str(ipaddress.ip_address(dstHost))
    elif atyp == b'\x03':
        dataLen = await aioRead(r, ReadMode.EXACT, exactLen=1, logHint=f'{logHint} fqdnLen')
        dataLen = dataLen[0]
        dstHost = await aioRead(r, ReadMode.EXACT, exactLen=dataLen, logHint=f'{logHint} fqdn') # 域名
        dstHost = dstHost.decode('utf8')
    elif atyp == b'\x04':
        dstHost = await aioRead(r, ReadMode.EXACT, exactLen=16, logHint=f'{logHint} ipv6') # ipv6
        dstHost = str(ipaddress.ip_address(dstHost))
    else:
        raise MyError(f'RECV ERRATYP={atyp} {logHint}')
    return dstHost

def socks5EncodeBindHost(bindHost): # 根据IP地址种类的不同，编码不同的报文
    atyp = b'\x03'
    hostData = None
    try:
        ipAddr = ipaddress.ip_address(bindHost)
        if ipAddr.version == 4:
            atyp = b'\x01'
            hostData = struct.pack('!L', int(ipAddr))   #ipv4，pack()函数用于将int型转为字符串
        else:
            atyp = b'\x04'
            hostData = struct.pack('!16s', ipaddress.v6_int_to_packed(int(ipAddr))) # ipv6
    except Exception:
        hostData = struct.pack(f'!B{len(bindHost)}s', len(bindHost), bindHost)
    return atyp, hostData

async def doClient(clientR, clientW):   # 处理与客户端的通信，两个参数分别是stream读写类的实例
    remoteR, remoteW = None, None
    try:
        clientHost, clientPort, *_ = clientW.get_extra_info('peername') # 读取客户端地址
        logHint = f'{clientHost} {clientPort}'
        firstByte = await aioRead(clientR, ReadMode.EXACT, exactLen=1, logHint=f'1stByte')  # 读取报文首字节（协议种类）
        if b'\x05' == firstByte:    # 使用socks5协议
            proxyType = 'SOCKS5'    # 以下是socks5建立连接的步骤，参考RFC1928
            logHint = f'{logHint} {proxyType}'
            numMethods = await aioRead(clientR, ReadMode.EXACT, exactLen=1, logHint='nMethod')  # 继续读1字节报文（支持的连接方式的数量）
            await aioRead(clientR, ReadMode.EXACT, exactLen=numMethods[0], logHint='methods')
            await aioWrite(clientW, b'\x05\x00', logHint='method.noAuth')   # 向客户端返回消息，告诉客户端自己支持非认证方式
            await aioRead(clientR, ReadMode.EXACT, exactData=b'\x05\x01\x00', logHint='verCmdRsv')  
            atyp = await aioRead(clientR, ReadMode.EXACT, exactLen=1, logHint='atyp')   # 得到目的主机地址种类
            dstHost = await socks5ReadDstHost(clientR, atyp, logHint='dstHost') # 读取不同种类的主机地址
            dstPort = await aioRead(clientR, ReadMode.EXACT, exactLen=2, logHint='dstPort')
            dstPort = int.from_bytes(dstPort, 'big')    # port转为int型
        else:   # HTTP tunnel
            line = await aioRead(clientR, ReadMode.LINE, logHint='1stLine') # 读一行，即建立HTTP connect请求的报文
            line = firstByte + line
            line = line.decode() # 从bytes型解码为str类型
            method, uri, proto, *_ = line.split()   # 报文示例： 'CONNECT  streamline.t-mobile.com:22  HTTP/1.1'
            if 'connect' == method.lower(): # CONNECT方式可支持https代理
                proxyType = 'HTTPS'
                logHint = f'{logHint} {proxyType}'
                dstHost, dstPort, *_ = uri.split(':')
                data = await aioRead(clientR, ReadMode.UNTIL, untilSep=b'\r\n\r\n', logHint='msg')
            else:
                raise MyError(f'RECV INVALID={line.strip()} EXPECT=CONNECT')    # 非connect方式的请求

        logHint = f'{logHint} {dstHost} {dstPort}'
        log.info(f'{logHint} connStart...')

        # 认证完成，与remoteProxy建立一个TCP连接
        remoteR, remoteW = await asyncio.open_connection(args.remoteHost, args.remotePort)
        firstDict = {'dst':dstHost, 'dport':dstPort, 'user':args.username, 'password':args.password}
        await aioWrite(remoteW, f'{json.dumps(firstDict)}\r\n'.encode(), logHint=f'1stLine')    # 向remoteProxy发送目的地址、用户名密码
        
        firstLine = await aioRead(remoteR, ReadMode.LINE, logHint=f'1stLine')
        bindHost, bindPort, *_ = firstLine.decode().rstrip().split()    # remoteProxy绑定目的主机成功
        log.info(f'{logHint} connSucc bind {bindHost} {bindPort}')

        if 'SOCKS5' == proxyType:   # 向Client返回reply消息
            atyp, hostData = socks5EncodeBindHost(bindHost)
            data = struct.pack(f'!ssss{len(hostData)}sH', b'\x05', b'\x00', b'\x00', atyp, hostData, int(bindPort))
            await aioWrite(clientW, data, logHint='reply')
        else:
            await aioWrite(clientW, f'{proto} 200 OK\r\n\r\n'.encode(), logHint='response')

        await asyncio.wait({    # 创建task以并发地传输信息，全双工方式
            asyncio.create_task(xferData(None, clientR, remoteW, logHint=f'{logHint} fromClient', upDirect=True)),
            asyncio.create_task(xferData(None, remoteR, clientW, logHint=f'{logHint} fromRemote', upDirect=False))
        })

    except MyError as exc:
        log.info(f'{logHint} {exc}')
    except json.JSONDecodeError as exc:
        log.info(f'{logHint} {exc}')
    except OSError:
        log.info(f'{logHint} connFail')
    except ValueError as exc:
        log.info(f'{logHint} {exc}')
    except Exception as exc:
        log.error(f'{traceback.format_exc()}')
        exit(1)
    await aioClose(clientW, logHint=logHint)
    await aioClose(remoteW, logHint=logHint)



async def calcBandwidth():  # 计算带宽数据
    global gSendBandwidth
    global gRecvBandwidth
    global gSendByteCount   # 负责在xferData函数中记录数据流量
    global gRecvByteCount
    while True:
        await asyncio.sleep(1)  # 每1s更新一次
        gSendBandwidth = gSendByteCount
        gRecvBandwidth = gRecvByteCount

        gSendByteCount = 0
        gRecvByteCount = 0


async def localConsole(ws, path): # 向guiconsole传递带宽数据，通过websocket
    global gSendBandwidth
    global gRecvBandwidth
    try:
        msg = await ws.recv()   # 接收gui建立连接的信息
        if msg != 'secret':     # 请求连接的消息不正确
            await ws.close()
            return
        while True: # 每隔1s向gui发送一次带宽信息
            await asyncio.sleep(1)
            msg = await ws.send(f'{gSendBandwidth} {gRecvBandwidth}')   
    except websockets.exceptions.ConnectionClosedError as exc:
        log.error(f'{exc}')
    except websockets.exceptions.ConnectionClosedOK as exc:
        log.error(f'{exc}')
    except Exception:
        log.error(f'{traceback.format_exc()}')
        exit(1)


async def localTask():  # 本地端异步任务
    if args.consolePort:   # 创建websocket服务器与gui通信 
        ws_server = await websockets.serve(localConsole, '127.0.0.1', args.consolePort)
        log.info(f'CONSOLE LISTEN {ws_server.sockets[0].getsockname()}')

    asyncio.create_task(calcBandwidth())    # 创建task，异步运行计算流量的函数
    
    # 使用asyncio的流API，启动与客户端的TCP通信服务
    srv = await asyncio.start_server(doClient, host=args.listenHost, port=args.listenPort)
    addrList = list([s.getsockname() for s in srv.sockets])
    log.info(f'LISTEN {addrList}')
    async with srv:
        await srv.serve_forever()   # 持续异步运行


async def xferData(bucket, srcR, dstW, *, logHint=None, upDirect): # 单向数据流传输，upDirect判断是否为上行流量
    global gSendByteCount
    global gRecvByteCount
    try:
        while True:
            tokenCount = 65535
            if bucket:  # local端无需对流量进行限制，只负责记录，故bucket为NONE
                tokenCount = await bucket.acquireToken(65535)
            data = await aioRead(srcR, ReadMode.MAX, maxLen=tokenCount, logHint='') # 每次读65535字节
            if bucket:
                leftToken = tokenCount - len(data)
                if leftToken:
                    bucket.releaseToken(leftToken)
            await aioWrite(dstW, data, logHint='')
            if upDirect:    # 上行
                gSendByteCount += len(data)
            else:           # 下行
                gRecvByteCount += len(data)
    except MyError as exc:
        log.info(f'{logHint} {exc}')

    await aioClose(dstW, logHint=logHint)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    _logFmt = logging.Formatter('%(asctime)s %(levelname).1s %(lineno)-3d %(funcName)-20s %(message)s', datefmt='%H:%M:%S') # 调试信息设置
    _consoleHandler = logging.StreamHandler()
    _consoleHandler.setLevel(logging.DEBUG)
    _consoleHandler.setFormatter(_logFmt)

    log = logging.getLogger(__file__)
    log.addHandler(_consoleHandler)
    log.setLevel(logging.DEBUG)

    _parser = argparse.ArgumentParser(description='socks5 https dual proxy')    # 命令行解析设置
    _parser.add_argument('-k', dest='consolePort', type=int, help='console listen port')
    _parser.add_argument('-l', dest='listenHost', help='proxy listen host default listen all interfaces')
    _parser.add_argument('-p', dest='listenPort', type=int, required=True, help='proxy listen port')
    _parser.add_argument('-u', dest='username', required=True, help='username')
    _parser.add_argument('-w', dest='password', help='password')
    _parser.add_argument('remoteHost', help='remote host')
    _parser.add_argument('remotePort', type=int, help='remote port')

    args = _parser.parse_args()

    if sys.platform == 'win32':     # 检查是否为windows操作系统
        asyncio.set_event_loop(asyncio.ProactorEventLoop())

    asyncio.run(localTask())    # 执行异步任务
