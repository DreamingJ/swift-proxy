'''
Copyright (c)2020, by Qogir, JMJ, MA71
All rights reserved.    
File Name: LocalProxy       
System Name: SwiftProxy
Date: 2020-12-01
Version: 1.0
Description: 远程代理服务器。该模块主要依赖aiosqlite和asyncio库。
'''
import aiosqlite
import asyncio
import json
import logging
import signal
import argparse
import collections
import traceback


from enum import Enum
ReadMode = Enum('ReadMod', ('EXACT', 'LINE', 'MAX', 'UNTIL'))   # 对应四种读模式

class MyError(Exception):   # 自定义一个异常类，raise抛出错误实例，便于追踪
    pass

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
        if ReadMode.EXACT == mode:  # 读精确的几字节
            exactLen = len(exactData) if exactData else exactLen
            data = await r.readexactly(exactLen)
            if exactData and data != exactData:
                raise MyError(f'recvERR={data} {logHint}')
        elif ReadMode.LINE == mode: # 读一行
            data = await r.readline()
        elif ReadMode.MAX == mode:  # 读大量字节，长度为maxLen
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

async def aioWrite(w, data, *, logHint=''): # 写报文
    try:
        w.write(data)
        await w.drain()     # 与write配套，用于立即清空缓冲区
    except ConnectionAbortedError as exc:
        raise MyError(f'sendEXC={exc} {logHint}')
    except ConnectionResetError as exc:
        raise MyError(f'recvEXC={exc} {logHint}')


User = collections.namedtuple('User', ['name', 'password', 'dataRate']) # namedtuple可直接用属性名表示item

gUserDict = dict()  # 存从数据库中取出的用户信息
gUserDictLock = asyncio.Lock()  # 对数据库访问加锁，避免冲突
gLinkCount = 0  # 同时连接remoteproxy的数量
gLeakyBucketDict = dict()   

class LeakyBucket:     # 令牌桶类，用于流量控制
    def __init__(self, tokenLimit):    # tokenlimit为用户数据库中的流量限制    
        self.tokenCount = tokenLimit    # 桶中剩余令牌数
        self.tokenLimit = tokenLimit    
        self.tokenSemaphore = asyncio.BoundedSemaphore(1)   # 创建信号量确保互斥访问

    def __del__(self):      # 删除该桶，信号量置空
        self.tokenLock = None
        self.tokenSemaphore = None
    
    async def acquireToken(self, count):    # 获取令牌，数量为count
        await self.tokenSemaphore.acquire() # 信号量的P操作
        tokenCount = 0                          # 此次消耗的令牌数
        tokenCount = min(self.tokenCount, count)    # 桶中令牌数可能小于所需
        self.tokenCount -= tokenCount
        if 0 < self.tokenCount:     # 若桶中令牌足够
            try:
                self.tokenSemaphore.release()   # 信号量V操作
            except ValueError:
                pass
        return tokenCount

    def releaseToken(self, count):  # 增加count数量的令牌
        self.tokenCount = min(self.tokenCount + count, self.tokenLimit)     # 数量不超过limit
        try:
            self.tokenSemaphore.release()
        except ValueError:
            pass

async def doLocal(localR, localW):  # 处理与localProxy的通信，两个参数分别是stream读写类的实例
    global gLinkCount
    gLinkCount += 1
    serverR, serverW = None, None
    try:
        localHost, localPort, *_ = localW.get_extra_info('peername')
        logHint = f'{localHost} {localPort}'
        # 读取local发来的目的地址、用户名密码
        firstLine = await aioRead(localR, ReadMode.LINE, logHint=f'1stLine')
        firstDict = json.loads(firstLine.strip().decode())  # 转为dict类型
        dstHost = firstDict.get('dst')
        dstPort = firstDict.get('dport')
        username = firstDict.get('user')
        password = firstDict.get('password')
        if not dstHost or not dstPort or not username or not password:
            raise MyError(f'ErrorFirst')

        user = gUserDict.get(username) # 得到数据库中该user的行
            
        if not user or user.password != password:   # 密码不符
            raise MyError(f'authFail {username} {password}')

        tokenLimit = user.dataRate if user.dataRate else args.tokenLimit # 若用户限制为空，tokenlimit从命令行取得

        logHint = f'{logHint} {dstHost} {dstPort}'
        log.info(f'{logHint} connStart...')

        # 与目标服务器建立TCP连接
        serverR, serverW = await asyncio.open_connection(dstHost, dstPort)
        bindHost, bindPort, *_ = serverW.get_extra_info('sockname')
        log.info(f'{logHint} connSucc bind {bindHost} {bindPort}')
        gLinkCount += 1

        await aioWrite(localW, f'{bindHost} {bindPort}\r\n'.encode(), logHint='1stLine')    # 向local回复bind成功的消息

        if username not in gLeakyBucketDict:    # 为用户分配其对应的令牌桶
            gLeakyBucketDict[username] = LeakyBucket(tokenLimit)
        bucket = gLeakyBucketDict.get(username) # 返回当前用户的令牌桶

        await asyncio.wait({    # 创建task以并发地传输信息，全双工方式
            asyncio.create_task(xferData(bucket, localR, serverW, logHint=f'{logHint} fromLocal', upDirect=True)),
            asyncio.create_task(xferData(bucket, serverR, localW, logHint=f'{logHint} fromServer', upDirect=False))
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
    await aioClose(localW, logHint=logHint)
    await aioClose(serverW, logHint=logHint)
    gLinkCount -= 1
    if serverR:
        gLinkCount -= 1

async def remoteTask(): # remoteProxy异步任务主函数 
    asyncio.create_task(dbSyncTask())       # 创建task，异步运行
    asyncio.create_task(tokenLeakTask())

    srv = await asyncio.start_server(doLocal, host=args.listenHost, port=args.listenPort)  # 启动与local的TCP通信服务
    addrList = list([s.getsockname() for s in srv.sockets]) 
    log.info(f'LISTEN {addrList}')
    async with srv:
        await srv.serve_forever()   # 持续异步运行

async def dbSyncTask(): # 数据库，同步gUserDict与 gLeakyBucketDict
    async with aiosqlite.connect(args.sqliteFile) as db:
        while True:
            await asyncio.sleep(1)  # 每秒1次同步
            userDict = dict()
            async with db.execute("SELECT name,password,dataRate FROM user;") as cursor:    # 执行查询
                async for row in cursor:
                    userDict[row[0]] = User(row[0], row[1], row[2]) # 以username作为key
            global gUserDict
            global gLeakyBucketDict
            gUserDict = userDict
            for name, user in gUserDict.items(): # name, user对应key,value
                if name in gLeakyBucketDict:    # 用户已连接，则返回其对应带宽限制
                    gLeakyBucketDict[name].tokenLimit = user.dataRate if user.dataRate else args.tokenLimit

async def tokenLeakTask():  # 异步task，生成令牌
    while True:
        await asyncio.sleep(1)
        for username, bucket in gLeakyBucketDict.items():
            bucket.releaseToken(bucket.tokenLimit)  # 每秒生成limit数量的令牌


async def xferData(bucket, srcR, dstW, *, logHint=None, upDirect): # 单向数据流传输，upDirect判断是否为上行流量
    try:
        while True:
            tokenCount = 65535
            if bucket:  # remote端有bucket对流量进行限制
                tokenCount = await bucket.acquireToken(65535)   # 一次读写的maxLen为65535，所以获取该数量令牌
            data = await aioRead(srcR, ReadMode.MAX, maxLen=tokenCount, logHint='') # 得到多少令牌，传输多少字节
            if bucket:
                leftToken = tokenCount - len(data)  # 没读到足够数据，因此有剩余令牌
                if leftToken:
                    bucket.releaseToken(leftToken)  # 剩余令牌加入令牌桶
            await aioWrite(dstW, data, logHint='')
            
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

    _parser = argparse.ArgumentParser(description='remote Proxy')       # 命令行解析设置
    _parser.add_argument('-d', dest='sqliteFile', default='user.db', help='user database sqlite file')  # 数据库文件名
    _parser.add_argument('-l', dest='listenHost', default='192.168.43.227', help='proxy listen host default listen all interfaces')  # 监听的主机地址
    _parser.add_argument('-p', dest='listenPort', type=int, default=8889, help='proxy listen port')
    _parser.add_argument('-t', dest='tokenLimit', type=int, default=999999, help='bytes/second per user')   # 默认的令牌桶流量限制

    args = _parser.parse_args()

    asyncio.run(remoteTask())
