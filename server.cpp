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
        //��������
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
    
    if(!send(clientSocket,(char *)&pk, sizeof(Public_key), 0)) //����RSA��Կ
    {
       cout<<"send rsa public key error"<<endl;
    }

    printf("�ѷ��͹�Կ\r\n");

    unsigned int* ak = new unsigned int[16];
    recv(clientSocket,(char*)ak,sizeof(unsigned int) * 16,0);
    
    string key = "";
    for(int i = 0; i < 16; i++)
    {
        key += (char)(Rsa::Decode(ak[i], sk));
    }
    cout<<key<<endl;
    aes.setKey(key);
    cout<<"�ѽ���des��Կ,��ʼͨ��"<<endl; 
    HANDLE hthread[2];
    hthread[0] = CreateThread(NULL, 0, serverRecv, (LPVOID) &clientSocket, 0, NULL);
    hthread[1] = CreateThread(NULL, 0, serverSend, (LPVOID) &clientSocket, 0, NULL);
    WaitForSingleObject(hthread[0], INFINITE);
    WaitForSingleObject(hthread[1], INFINITE);

}
int main()
{
    WSADATA wsaData;//WSAStartup�������ú󷵻ص�Windows Sockets���ݵ����ݽṹ 
    WSAStartup(MAKEWORD(2, 2), &wsaData);//����ʹ��socket2.2�汾
    //�����������׽���
    SOCKET serverSocket;
    //��ַ����ΪAD_INET����������Ϊ��ʽ(SOCK_STREAM)��Э�����TCPs
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET)
    {
        //�׽��ִ���ʧ�ܣ�
        WSACleanup();
        return 0;
    }
    SOCKADDR_IN serverAddr;
    serverAddr.sin_family = AF_INET;      //IP��ʽ
    USHORT uPort = 8888;
    serverAddr.sin_port = htons(uPort);   //�󶨶˿ں�
    serverAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");

    cout<<"This is a server window"<<endl;

    if (bind(serverSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)  //��������
    {
        cout<<"��ʧ��"<<endl;
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
            cout << "����ʧ��" << endl;
            return 0;
    }
    exchangekey(clientSocket);
    
    WSACleanup();
    system("pause");
    return 0;
}