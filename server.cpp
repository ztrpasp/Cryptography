#include<iostream>
#include<stdio.h>
#include<windows.h>
#include<time.h>
#include<winsock.h>
#include<string.h>
#include <unistd.h>
#include "AES.h"
#include "AES_imp.h"
#include "RSA.h"
#pragma comment(lib, "ws2_32.lib")
#define maxClient 10

AES aes(AESKeyLength::AES_128);
Rsa rsa;
DWORD WINAPI serverSend(LPVOID lparam) {
    
}

DWORD WINAPI serverRecv(LPVOID lparam) {
    SOCKET *socket = (SOCKET *) lparam;
    char recvbuf[1024];
    memset(recvbuf,0,sizeof(recvbuf));
    while(true)
    {
        memset (recvbuf,0,sizeof(recvbuf));
        //接收内容
        recv(*socket,recvbuf,sizeof(recvbuf),0);
        aes.decode(recvbuf);
    }
}

void exchangekey(int clientSocket)
{
    rsa.init();
    Public_key pk = rsa.get_pk();
    Secret_key sk = rsa.get_sk();
    rsa.check_key();
    
    if(!send(clientSocket,(char *)&pk, sizeof(Public_key), 0)) //发送RSA公钥
    {
       cout<<"send rsa public key error"<<endl;
    }

    printf("已发送公钥\r\n");

    unsigned int* ak = new unsigned int[16];
    recv(clientSocket,(char*)ak,sizeof(unsigned int) * 16,0);
    
    string key = "";
    for(int i = 0; i < 16; i++)
    {
        key += (char)(Rsa::Decode(ak[i], sk));
    }
    cout<<key<<endl;
    aes.setKey(key);
    cout<<"已接受des密钥,开始通信"<<endl; 
    HANDLE hthread[2];
    hthread[0] = CreateThread(NULL, 0, serverRecv, (LPVOID) &clientSocket, 0, NULL);
    hthread[1] = CreateThread(NULL, 0, serverSend, (LPVOID) &clientSocket, 0, NULL);
    WaitForSingleObject(hthread[0], INFINITE);
    WaitForSingleObject(hthread[1], INFINITE);

}
int main()
{
    WSADATA wsaData;//WSAStartup函数调用后返回的Windows Sockets数据的数据结构 
    WSAStartup(MAKEWORD(2, 2), &wsaData);//声明使用socket2.2版本
    //建立服务器套接字
    SOCKET serverSocket;
    //地址类型为AD_INET，服务类型为流式(SOCK_STREAM)，协议采用TCPs
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET)
    {
        //套接字创建失败；
        WSACleanup();
        return 0;
    }
    SOCKADDR_IN serverAddr;
    serverAddr.sin_family = AF_INET;      //IP格式
    USHORT uPort = 8888;
    serverAddr.sin_port = htons(uPort);   //绑定端口号
    serverAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");

    cout<<"This is a server window"<<endl;

    if (bind(serverSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)  //建立连接
    {
        cout<<"绑定失败"<<endl;
        closesocket(serverSocket);
        WSACleanup();
        return 0;
    }
    SOCKADDR_IN clientAddr;  
    int clientAddrlen = sizeof(clientAddr);
    listen(serverSocket, maxClient);
    SOCKET clientSocket = accept(serverSocket, (SOCKADDR*)&clientAddr,&clientAddrlen);
    if (clientSocket == SOCKET_ERROR) 
    {
            cout << "连接失败" << endl;
            return 0;
    }
    exchangekey(clientSocket);
    
    WSACleanup();
    system("pause");
    return 0;
}