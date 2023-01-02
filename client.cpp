#include<iostream>
#include<stdio.h>
#include<windows.h>
#include<time.h>
#include<winsock.h>
#include<string.h>
#include <random>

#include "AES.h"
#include "AES_imp.h"
#include "RSA.h"
#pragma comment(lib, "ws2_32.lib")


AES aes(AESKeyLength::AES_128);
Rsa rsa;


string strRand(int length) {			
    char tmp;							
    string buf;						
    
    random_device rd;					
    default_random_engine random(rd());	
    
    for (int i = 0; i < length; i++) {
        tmp = random() % 52;	
        if (tmp < 26) {			
            tmp += 'a';
        } else {				
            tmp -= 26;
            tmp += 'A';
        }
        buf += tmp;
    }
    return buf;
}

DWORD WINAPI clientSend(LPVOID lparam) {
    SOCKET *socket = (SOCKET *) lparam;
    char sendbuf[1024];
    while(true)
    {
        memset(sendbuf,0,sizeof(sendbuf));
        cout<<"��������Ϣ"<<endl;
        cin>>sendbuf;
        int length = strlen(sendbuf);
        char * temp = aes.encode(sendbuf,length+1);
        send(*socket,temp,sizeof(sendbuf),0);
    }
    
}

DWORD WINAPI clientRecv(LPVOID lparam) {
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


void exchangekey(SOCKET clientSocket)
{
    string key = strRand(16);
    cout<<"����Aes��Կ: "<<key<<endl;  
    Public_key pk;
    if(recv(clientSocket, (char *)&pk, sizeof(Public_key),0) < 0)
    {
        cout<<"recv rsa public key erreor"<<endl;
    }
    printf("���յ���Կ��(n, e): (%d, %d)\r\n", pk.n, pk.e);
    unsigned int *crypto = new unsigned int[16];
    const char* ak = key.c_str();

    for(int i = 0; i < 16; i++)
    {
        char a = ak[i];
        int b = (int)a;
        crypto[i] = Rsa::Encode(b, pk);
    }
    if(!send(clientSocket, (char *)crypto, sizeof(unsigned int) * 16, 0))
        cout<<" send aes key error"<<endl;
    cout<<key<<endl;
    aes.setKey(key);
    cout<<"�ѳɹ�����aes��Կ,���ڿ�ʼͨ��"<<endl;
    HANDLE hthread[2];
    hthread[0] = CreateThread(NULL, 0, clientRecv, (LPVOID) &clientSocket, 0, NULL);
    hthread[1] = CreateThread(NULL, 0, clientSend, (LPVOID) &clientSocket, 0, NULL);
    WaitForSingleObject(hthread[0], INFINITE);
    WaitForSingleObject(hthread[1], INFINITE);

}
int main()
{
    WSADATA wsaData;//WSAStartup�������ú󷵻ص�Windows Sockets���ݵ����ݽṹ 
    WSAStartup(MAKEWORD(2, 2), &wsaData);//����ʹ��socket2.2�汾
    //�����׽���
    SOCKET clientSocket;
    //��ַ����ΪAD_INET����������Ϊ��ʽ(SOCK_STREAM)��Э�����TCPs
    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET)
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


    cout<<"This is a client window"<<endl;

    if (connect(clientSocket, (SOCKADDR *) &serverAddr, sizeof(SOCKADDR)) == SOCKET_ERROR) { //��������
        cout << "����ʧ��" << endl;
        system("pause");
        return 0;
    }
    else{cout<<"���ӳɹ�"<<endl;}

    exchangekey(clientSocket);

    
    
    system("pause");
    closesocket(clientSocket);

    WSACleanup();

    return 0;
}