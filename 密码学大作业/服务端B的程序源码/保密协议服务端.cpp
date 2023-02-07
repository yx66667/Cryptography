#include <iostream>
#include <stdlib.h>
#include "bigint.h"
#include "AES.h"
#include <ctime>
#include<winsock.h>  
#include<string.h>  
#pragma comment(lib, "ws2_32.lib")  
//����ws2_32.lib��  
using namespace std;
DWORD WINAPI receiveThread(LPVOID IpParameter);
char buffer[1024] = { 0 };  
int relen = 0;  
int selen = 0;
char client_name[32] = { 0 };   
//�����׽���  
SOCKET ServerSocket;
byte key1[16] = {0}; //AES�Ự��Կ

int main()
{
	BigInt n1; //n1�Ƿ����B�Ĺ�Կ
    n1.data[31] = 0x8C953ABC;
	n1.data[30] = 0x93ECDE71;
	n1.data[29] = 0x352D2801;
	n1.data[28] = 0xA642D4A7;
    n1.data[27] = 0x10AB939D;
	n1.data[26] = 0xD172B70B;
	n1.data[25] = 0xD5116978;
	n1.data[24] = 0x5E0401E0;
	n1.data[23] = 0x3CE7072F;
	n1.data[22] = 0x09B2E5F2 ;
	n1.data[21] = 0x382233F7;
	n1.data[20] = 0xCBB735A7;
	n1.data[19] = 0xA142A610;
	n1.data[18] = 0x80279237;
	n1.data[17] = 0xB426C8A9;
	n1.data[16] = 0xD65D897D;
	n1.data[15] = 0x2639A461;
	n1.data[14] = 0x16C87093;
	n1.data[13] = 0xF4F1D109;
	n1.data[12] = 0x13A86D67;
	n1.data[11] = 0xD1246579;
	n1.data[10] = 0x7783BA71;
	n1.data[9] = 0xFF73B1FF;
	n1.data[8] = 0xAE457979;
	n1.data[7] = 0x699F3471;
	n1.data[6] = 0xD5178984;
	n1.data[5] = 0x59D22843;
	n1.data[4] = 0x72BA4152;
	n1.data[3] = 0xE272270A;
	n1.data[2] = 0x41F6AD5D;
	n1.data[1] = 0x66F5DCBC;
    n1.data[0] = 0xFC6240F3;

	cout << "�����B��ԿnΪ�� " << endl;
	//16������ʽ��ʾ
	n1.display();
	cout << endl;

	cout << "��Կe����Կd " << endl;

	//eΪ�����B�Ĺ���Կ
	BigInt e1;
	e1.data[15] = 0x80DCBC67;
	e1.data[14] = 0xE4059177;
	e1.data[13] = 0x1645AC68;
	e1.data[12] = 0x2F3DA60B;
	e1.data[11] = 0x30C2F2C2;
	e1.data[10] = 0x36787FD0;
	e1.data[9] = 0xD1D286FE;
	e1.data[8] = 0x04546776;
	e1.data[7] = 0x64C117EE;
	e1.data[6] = 0x3B03DD46;
	e1.data[5] = 0xB8A5DA06;
	e1.data[4] = 0x87E545BE;
	e1.data[3] = 0x6284F425;
	e1.data[2] = 0x0E429B3E;
	e1.data[1] = 0x6CADADFE;
	e1.data[0] = 0xEDA0C9F3;

	//dΪ����Կ
	BigInt d1;
	d1.data[31] = 0x3B11D55B;
	d1.data[30] = 0x63157F7C;
	d1.data[29] = 0x2FC48387;
	d1.data[28] = 0x87F778FA;
	d1.data[27] = 0x421A719B;
	d1.data[26] = 0x545736E7;
	d1.data[25] = 0xE6770B2D;
	d1.data[24] = 0x85961B9B;
	d1.data[23] = 0x8B819E34;
	d1.data[22] = 0x3573D250;
	d1.data[21] = 0x6F861C81;
	d1.data[20] = 0xB1B94028;
	d1.data[19] = 0xEE830D50;
	d1.data[18] = 0x38BA5DDA;
    d1.data[17] = 0x15750122;
	d1.data[16] = 0xD1881C42;
    d1.data[15] = 0x1293C132;
	d1.data[14] = 0x72971492;
	d1.data[13] = 0xD8EE5A52;
	d1.data[12] = 0x39AE5E72;
	d1.data[11] = 0xB98CB3B3;
	d1.data[10] = 0xA824F320;
	d1.data[9] = 0x99FAC984;
	d1.data[8] = 0x9D012A48;
	d1.data[7] = 0x199D53ED;
	d1.data[6] = 0xEFACD22C;
	d1.data[5] = 0xC8A353E5;
	d1.data[4] = 0x32380342;
	d1.data[3] = 0x5357D97D;
	d1.data[2] = 0x1C97A7E8;
	d1.data[1] = 0x9E9A4E1E;
	d1.data[0] = 0xB31CB75B;
	cout << "�����B�Ĺ�ԿeΪ�� " << endl;
	//16������ʽ��ʾ
	e1.display();
	cout << endl;

	cout << "�����B��˽ԿdΪ�� " << endl;
	//16������ʽ��ʾ
	d1.display();
	cout << endl;

	BigInt n2; //n2�ǿͻ���A�Ĺ�Կ
    n2.data[31] = 0x42D49CBA;
	n2.data[30] = 0xA4283F78;
	n2.data[29] = 0xB3D21586;
	n2.data[28] = 0x7C252142;
    n2.data[27] = 0x557106EC;
	n2.data[26] = 0x1DB76F64;
	n2.data[25] = 0x0D100F45;
	n2.data[24] = 0x3C3ED289;
	n2.data[23] = 0x81C06C55;
	n2.data[22] = 0xE8F491A4;
	n2.data[21] = 0x81745306;
	n2.data[20] = 0xEF2868A0;
	n2.data[19] = 0xAD8AC219;
	n2.data[18] = 0xE54B95AA;
	n2.data[17] = 0xD5E47632;
	n2.data[16] = 0xDCB3F0B0;
	n2.data[15] = 0xF192E827;
	n2.data[14] = 0x51277E59;
	n2.data[13] = 0xC090F86C;
	n2.data[12] = 0x2250F711;
	n2.data[11] = 0xC2D40989;
	n2.data[10] = 0xB49941FC;
	n2.data[9] = 0x4F159B37;
	n2.data[8] = 0xB67ED12D;
	n2.data[7] = 0x71F97CFA;
	n2.data[6] = 0xF035548C;
	n2.data[5] = 0x42A066B2;
	n2.data[4] = 0x31540526;
	n2.data[3] = 0x58B896BF;
	n2.data[2] = 0x3E25C2D8;
	n2.data[1] = 0x9BF507C5;
    n2.data[0] = 0x1627A383;

	cout << "�ͻ���A�Ĺ�ԿnΪ�� " << endl;
	//16������ʽ��ʾ
	n2.display();
	cout << endl;

	//e2Ϊ�ͻ���A�Ĺ���Կ
	BigInt e2;
	e2.data[15] = 0x1197CB94;
	e2.data[14] = 0xD7DB8F4B;
	e2.data[13] = 0xF5849A20;
	e2.data[12] = 0xA480C81F;
	e2.data[11] = 0x22AFA4BB;
	e2.data[10] = 0x3B434BB0;
	e2.data[9] = 0xF30B6112;
	e2.data[8] = 0x091251AF;
	e2.data[7] = 0xF7CA13A3;
	e2.data[6] = 0xE5601FF3;
	e2.data[5] = 0x289C9E3F;
	e2.data[4] = 0xE160D111;
	e2.data[3] = 0x88639DBE;
	e2.data[2] = 0x929E06C2;
	e2.data[1] = 0xC6422DAC;
	e2.data[0] = 0xF78D50B1;
	
	cout << "�ͻ���A�Ĺ�ԿeΪ�� " << endl;
	//16������ʽ��ʾ
	e2.display();
	cout << endl;
 
		WSADATA wsaData; //��ű�WSAStartup�������ú󷵻ص�Windows Sockets���ݵ����ݽṹ  
		WSAStartup(MAKEWORD(2, 2), &wsaData);//����ʹ��socket2.2�汾 
	    //��ַ����ΪAD_INET����������Ϊ��ʽ(SOCK_STREAM)��Э�����TCP 
	    ServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);  
	    if (ServerSocket == INVALID_SOCKET)  
	    {  
	        cout << "�׽��ִ���ʧ��";  
	        WSACleanup();  
	        return 0;  
	    }  
	  
	    SOCKADDR_IN ServerAddr;  
	    ServerAddr.sin_family = AF_INET;     //ָ��IP��ʽ  
	    USHORT uPort = 8888;                 //�����������˿�  
	    ServerAddr.sin_port = htons(uPort);   //�󶨶˿ں�  
	    ServerAddr.sin_addr.S_un.S_addr = INADDR_ANY;  
	    if (bind(ServerSocket, (SOCKADDR*)&ServerAddr, sizeof(ServerAddr)) == SOCKET_ERROR)  //��������  
	    {  
	        cout << "��ʧ��";  
	        closesocket(ServerSocket);  
	        return 0;  
	    }  
	    char server_name[32] = { 0 };  
	    cout << "������������֣�";  
	    cin.getline(server_name,32);  
	  
	    /*��ʼ����*/  
	    listen(ServerSocket, 1);  
	  
	    /*�ȴ�����*/   
	    SOCKET ClientSocket;  
	    SOCKADDR_IN ClientAddr;  
	    int ClientAddrlen = sizeof(ClientAddr);  
	    ClientSocket = accept(ServerSocket,(SOCKADDR*)&ClientAddr,&ClientAddrlen);  
	    cout << "�ȴ�����...\n";  
	    if (ClientSocket == INVALID_SOCKET)  
	    {  
	        cout << "�ͻ��˷������󣬷�������������ʧ�ܣ�\n" << WSAGetLastError();  
	        closesocket(ServerSocket);  
	        WSACleanup();  
	        return 0;  
	    }  
	    else  
	    {  
	        cout << "�ͷ�����������������ӳɹ���\n" ;  
	    }    
	    /*ͨ�����������ӽ���ͨ��*/  
	    //���ͺͽ��ܿͻ��������˵�����  
	    selen=send(ClientSocket, server_name, strlen(server_name), 0);  
	    relen=recv(ClientSocket, client_name, sizeof(client_name), 0);  
	    client_name[relen] = '\0';  
		relen = recv(ClientSocket, buffer, sizeof(buffer), 0); 
		cout<<"�����յ����Կͻ��˵�RSA���ܺ��AES�Ự��Կ��"<<endl;
		cout<<buffer<<endl;
		BigInt c;
		for(int i = 0; i < 32; i++){ //�ַ�������ת����int�ͣ�����c��
			c.data[i] = 0;
			int temp = 0;
			for(int j = 0; j < 8; j++){
				if(buffer[i*8+j]>='0' && buffer[i*8+j]<='9'){
					temp = buffer[i*8+j] - '0';
					for(int k = 1 ; k <=(7-j); k++){
						temp *=16;
					}
					c.data[i] += temp;
				}
				if(buffer[i*8+j]>='a' && buffer[i*8+j]<='f'){
					temp = buffer[i*8+j] - 'a' + 10;
					for(int k = 1 ; k <= 7-j; k++){
						temp *=16;
					}
					c.data[i] += temp;
				}
			}
		}

		cout<<"�÷����B��˽Կd��c���ܣ��õ����ܺ�m1"<<endl;
		BigInt m1 = PowerMode(c, d1, n1);
		cout << "���ܺ��m1Ϊ��" << endl;
		//16������ʽ��ʾ
		m1.display();
		cout << endl;

		for(int i = 0 ; i <= 3; i++){
			key1[i*4] = (m1.data[3-i] >> 24) & 0xFF;
			key1[i*4+1] = (m1.data[3-i] >> 16) & 0xFF;
			key1[i*4+2] = (m1.data[3-i]>> 8) & 0xFF;
			key1[i*4+3] = m1.data[3-i] & 0xFF;
		}
	cout<<"AES�Ự��ԿΪ��";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", key1[i]);
	}
	cout<<endl;



	    AES aes1(key1,_128BIT);
	    //����������Ϣ�߳�
	    CloseHandle(CreateThread(NULL, NULL, receiveThread, (LPVOID)&ClientSocket, 0, 0));
		//������Ϣ�����߳�
	        while (1) {  
	            memset(buffer, 0, sizeof(buffer));
				char m[20] = {0};
	            cin.getline(m,20);  
				cout << "��"<<server_name << "��: "<<m<<endl; 

				byte c1[16];
				byte *m0 =new byte[16];
				StringToHex(m,m0);
				cout<<"��Ҫ���͵���Ϣת��Ϊ16���ƣ�";
				for(int i = 0; i < 16; i++){
					printf("0x%02X ", m0[i]);
				}
				cout<<endl;

				aes1.encrypt(m0,c1);
				cout<<"AES���ܺ�õ���ʮ��������Ϊ��";
				for(int i = 0; i < 16; i++){
					printf("0x%02X ", c1[i]);
				    if(c1[i]<0x10){
						sprintf(buffer+i*2,"%s","0");
						sprintf(buffer+i*2+1,"%x",c1[i]);
					}else{
						sprintf(buffer+i*2,"%x", c1[i]);
					}
				}
				cout<<endl;
				cout<<"���͵ļ�������Ϊ��"<<buffer<<endl;
				cout<<endl;

	            //������Ϣ  
	            if(strcmp(m, "exit") == 0)  
	            {  
	                selen = send(ClientSocket, buffer, sizeof(buffer), 0);  
	                cout << "������3����˳�" << endl;  
	                Sleep(3000);  
	                closesocket(ServerSocket);  
	                closesocket(ClientSocket);  
	                WSACleanup();  
	                return 0;  
	            }  
	            selen = send(ClientSocket, buffer, sizeof(buffer), 0);  
	        }   

	system("pause");
	return 0;
}
DWORD WINAPI receiveThread(LPVOID IpParameter) //������Ϣ���߳�
{
	SOCKET ClientSocket = *(SOCKET*)IpParameter;
	AES aes1(key1,_128BIT);
	while (1)  
	{  
		 char c[1024] = {0};
	     memset(buffer, 0, sizeof(buffer));//��ÿ�ν���ǰ����֮ǰ��buf������գ����⻺��������  
	     relen = recv(ClientSocket, c, sizeof(c), 0); 
		 cout<<"���յ���AES��������Ϊ��"<<c<<endl;
		 byte c1[16];
		 byte temp = 0;
		 for(int i = 0 ; i < 32 ; i = i+2){ //�����յ�������ת��Ϊbyte��ʽ
			 if(c[i]>='0'&& c[i]<='9'){
				 temp = (c[i] - '0') * 16;
			 }
			 if(c[i]>='a'&& c[i]<='f'){
				 temp = (c[i] - 'a' + 10) * 16;
			 }
			 if(c[i+1]>='0'&& c[i+1]<='9'){
				 temp += (c[i+1] - '0');
			 }
			 if(c[i+1]>='a'&& c[i+1]<='f'){
				 temp += (c[i+1] - 'a' + 10);
			 }
			 c1[i/2] = temp;
		 }
		 byte m_1[16];
		 aes1.decrypt(c1,m_1);
		 cout<<"AES���ܺ�õ�����Ϊ��";
		 for(int i = 0; i < 16; i++){
			printf("0x%02X ", m_1[i]);
		 }
		 cout<<endl;
		 HexToString(buffer,m_1);

	     //������Ϣ  
	     if (strcmp(buffer, "exit") == 0)//������Ϣ����exit���˳�  
	     {  
	          cout << "�Է��Ѿ��Ͽ�����" << endl;    
	          return 0;  
	     }  
		 cout << "��"<<client_name << "��: ";  
	     cout << buffer << endl;  
		 cout<<endl;
	}  
}