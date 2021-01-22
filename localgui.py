'''
Copyright (c)2020, by Qogir, JMJ, MA71
All rights reserved.    
File Name: LocalProxy       
System Name: SwiftProxy
Date: 2020-12-01
Version: 2.0
Description: 用户操作界面。此模块使用PyQt5库编写，并使用QProcess类启动外部程序localProxy，从而简化程序流程，提升程序健壮性与代码可读性。与用户在界面窗口中输入账户密码，并指定本地IP、端口及远程IP、端口，LocalGUI就会将数据呈递给LocalProxy。此界面中也会实时显示连接状态，每秒上传数据量及下载数据量。
'''

import os
import sys
import logging
import traceback
import humanfriendly
from PyQt5.QtGui import * 
from PyQt5.QtCore import *
from PyQt5.QtNetwork import *
from PyQt5.QtWidgets import *
from PyQt5.QtWebSockets import *


class Window(QDialog):
    def __init__(self, parent=None):
        QDialog.__init__(self, parent)

        self.setUI()

        self.process = QProcess()
        self.process.setProcessChannelMode(QProcess.MergedChannels)
        self.process.finished.connect(self.processFinished) # localProxy进程结束
        self.process.started.connect(self.processStarted)   # 进程启动
        self.process.readyReadStandardOutput.connect(self.processReadyRead)

    def setUI(self):
        self.resize(500,500)
        self.setWindowOpacity(10) # 设置窗口透明度

        self.startBtn = QPushButton(self)
        self.startBtn.setText('Connect')
        self.startBtn.clicked.connect(self.startClicked)
        
        self.stopBtn = QPushButton(self)
        self.stopBtn.setText('Disconnect')
        self.stopBtn.clicked.connect(self.stopClicked)
        self.stopBtn.setDisabled(True)

        self.sendBandwidthLine = QLabel()
        self.recvBandwidthLine = QLabel()
        self.processIdLine = QLabel()

        self.listenHostLine = QLineEdit('127.0.0.1')
        self.listenPortLine = QLineEdit('8888')
        self.listenPortLine.setPlaceholderText('输入1025~65535')
        self.remoteHostLine = QLineEdit('127.0.0.1')
        self.remotePortLine = QLineEdit('8889')
        self.remotePortLine.setPlaceholderText('输入1025~65535')
        self.consolePortLine = QLineEdit('9000') # 使用9000端口进行websocket通信

        self.usernameLine = QLineEdit('admin')
        self.passwordLine = QLineEdit('123456')
        self.passwordLine.setEchoMode(QLineEdit.Password)

        selfPIdLine = QLabel(str(os.getpid()))

        R1_widget = QGroupBox('Settings')
        flayout_R1 = QFormLayout()
        flayout_R1.setAlignment(Qt.AlignCenter)
        flayout_R1.addRow(QLabel('监听主机'), self.listenHostLine)
        flayout_R1.addRow(QLabel('端口'), self.listenPortLine)
        flayout_R1.addRow(QLabel('远端地址'), self.remoteHostLine)
        flayout_R1.addRow(QLabel('端口'), self.remotePortLine)
        R1_widget.setLayout(flayout_R1)

        L1_widget = QGroupBox('Log in')
        flayout_L1 = QFormLayout()
        flayout_L1.addRow(QLabel('用户名'), self.usernameLine)
        flayout_L1.addRow(QLabel('密码'), self.passwordLine)
        flayout_L1.addRow(QLabel(''))
        flayout_L1.addRow(self.startBtn)
        flayout_L1.addRow(QLabel(''))
        flayout_L1.addRow(self.stopBtn)
        L1_widget.setLayout(flayout_L1)

        R2_widget = QGroupBox('Process ID')
        flayout_R2 = QFormLayout()
        flayout_R2.addRow(QLabel('Self Process ID :'), selfPIdLine)
        flayout_R2.addRow(QLabel(''))
        flayout_R2.addRow(QLabel('Proxy Process ID:'), self.processIdLine)
        R2_widget.setLayout(flayout_R2)

        L2_widget = QGroupBox('Information')
        flayout_L2 = QFormLayout()
        flayout_L2.addRow(QLabel('上传速率：'), self.sendBandwidthLine)
        flayout_L2.addRow(QLabel(''))
        flayout_L2.addRow(QLabel('下载速率：'), self.recvBandwidthLine)
        L2_widget.setLayout(flayout_L2)

        Alayout = QHBoxLayout()
        Alayout.addWidget(R1_widget)
        Alayout.addWidget(L1_widget)

        Blayout = QHBoxLayout()
        Blayout.addWidget(R2_widget)
        Blayout.addWidget(L2_widget)

        Clayout = QVBoxLayout()
        Clayout.addLayout(Alayout)
        Clayout.addLayout(Blayout)

        Clayout.setStretch(0,3) 
        Clayout.setStretch(1,7)
        Clayout.setSpacing(10)
        self.setLayout(Clayout)

    def processReadyRead(self):
        data = self.process.readAll()
        try:
            msg = data.data().decode().strip()
            log.debug(f'msg={msg}')
        except Exception as exc:
            log.error(f'{traceback.format_exc()}')
            exit(1)
        
    
    def processStarted(self):
        process = self.sender() # 此处等同于 self.process 只不过使用sender适应性更好
        processId = process.processId()
        log.debug(f'pid={processId}')
        self.startBtn.setText('Connected')
        self.processIdLine.setText(str(processId))

        self.websocket = QWebSocket()
        self.websocket.connected.connect(self.websocketConnected)
        self.websocket.disconnected.connect(self.websocketDisconnected)
        self.websocket.textMessageReceived.connect(self.websocketMsgRcvd)
        self.websocket.open(QUrl(f'ws://127.0.0.1:{self.consolePortLine.text()}/')) # 连接到localProxy代理服务器，本机的9000端口

    def processFinished(self):
        process = self.sender()
        processId = process.processId()
        self.processIdLine.setText('')
        log.debug(f'end process {processId}')
        self.process.kill()
        self.websocket.close()

    def processBytesWritten(self, byteCount):
        log.debug(f'bytes={byteCount}')
    
    def processErrorOccurred(self, error):
        log.debug(f'err={error}')

    def startClicked(self):
        self.startBtn.setDisabled(True)
        self.stopBtn.setEnabled(True)
        btn = self.sender()
        text = btn.text().lower()
        listenPort = self.listenPortLine.text()
        username = self.usernameLine.text()
        password = self.passwordLine.text()
        consolePort = self.consolePortLine.text()
        remoteHost = self.remoteHostLine.text()
        remotePort = self.remotePortLine.text()
        pythonExec = os.path.basename(sys.executable)
        # 从localgui启动localproxy直接使用-w 提供用户密码，不再使用命令行交互输入，因为有些许问题
        cmdLine = f'{pythonExec} localProxy.py -p {listenPort} -u {username} -w {password} -k {consolePort} {remoteHost} {remotePort}'
        log.debug(f'cmd={cmdLine}')
        self.process.start(cmdLine) # 开启进程，执行命令行内容

    def stopClicked(self):
        self.startBtn.setEnabled(True)
        self.stopBtn.setDisabled(True)
        self.startBtn.setText('Connect')
        self.process.kill()

    def websocketConnected(self):
        self.websocket.sendTextMessage('secret')

    def websocketDisconnected(self):
        self.process.kill()

    def websocketMsgRcvd(self, msg):
        log.debug(f'msg={msg}')
        sendBandwidth, recvBandwidth, *_ = msg.split()
        nowTime = QDateTime.currentDateTime().toString('hh:mm:ss')
        self.sendBandwidthLine.setText(f'{nowTime} {humanfriendly.format_size(int(sendBandwidth))}')
        self.recvBandwidthLine.setText(f'{nowTime} {humanfriendly.format_size(int(recvBandwidth))}')
    
    def readQss(style):
        with open(style,'r',encoding='UTF-8') as f:
            return f.read()
        
if __name__ == '__main__':

    _logFmt = logging.Formatter('%(asctime)s %(levelname).1s %(lineno)-3d %(funcName)-20s %(message)s', datefmt='%H:%M:%S')
    _consoleHandler = logging.StreamHandler()
    _consoleHandler.setLevel(logging.DEBUG)
    _consoleHandler.setFormatter(_logFmt)

    log = logging.getLogger(__file__)
    log.addHandler(_consoleHandler)
    log.setLevel(logging.DEBUG)

    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = Window()
    styleFile = './style.qss'
    qssStyle = Window.readQss(styleFile)
    window.setWindowTitle('SwiftProxy')
    window.setStyleSheet(qssStyle)
    window.show()
    sys.exit(app.exec_())
