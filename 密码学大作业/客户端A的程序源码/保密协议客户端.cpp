#include <iostream>
#include <stdlib.h>
#include "bigint.h"
#include "AES.h"
#include <ctime>
#include<winsock.h>  
#include<string.h>  
#pragma comment(lib, "ws2_32.lib")  
using namespace std;
DWORD WINAPI receiveThread(LPVOID IpParameter);  
char server_name[32] = { 0 };  
char buffer[1024] = { 0 };  
int relen = 0;  
int selen = 0;
byte key1[16] = { //��ʼ��Կ00012001710198aeda79171460153594
        0x00, 0x01, 0x20, 0x01,
        0x71, 0x01, 0x98, 0xae,
        0xda, 0x79, 0x17, 0x14,
        0x60, 0x15, 0x35, 0x94
};
AES aes1(key1,_128BIT);

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
	
	cout << "�����B�Ĺ�ԿeΪ�� " << endl;
	//16������ʽ��ʾ
	e1.display();
	cout << endl;
	/*
	//d1Ϊ�����B����Կ���ͻ���AӦ����֪
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
	cout << "�����B����ԿdΪ�� " << endl;
	//16������ʽ��ʾ
	d1.display();
	cout << endl;
	*/

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

	cout << "��Կe����Կd " << endl;

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

	//dΪ����Կ
	BigInt d2;
	d2.data[31] = 0x1BC0F905;
	d2.data[30] = 0x68F17E30;
	d2.data[29] = 0x3C113EC5;
	d2.data[28] = 0x1394A2BB;
	d2.data[27] = 0xC66A1C76;
	d2.data[26] = 0x2ECA0FD9;
	d2.data[25] = 0xB0251C5B;
	d2.data[24] = 0x0D3AF482;
	d2.data[23] = 0xFD9A7D77;
	d2.data[22] = 0xB6BFF877;
	d2.data[21] = 0x8BA3149B;
	d2.data[20] = 0x623C1D5A;
	d2.data[19] = 0x3E091627;
	d2.data[18] = 0xE681C76B;
	d2.data[17] = 0xCD0BC17D;
    d2.data[16] = 0x21360856;
	d2.data[15] = 0xFA7C2744;
    d2.data[14] = 0x2956634A;
	d2.data[13] = 0xBF288636;
	d2.data[12] = 0xD6000577;
	d2.data[11] = 0x3E23D1EA;
	d2.data[10] = 0x5B31792F;
	d2.data[9] = 0x84E7B350;
	d2.data[8] = 0x3AD092DD;
	d2.data[7] = 0x80578B8B;
	d2.data[6] = 0xD4F907C4;
	d2.data[5] = 0xCA92BBEC;
	d2.data[4] = 0x10014CE7;
	d2.data[3] = 0x63469904;
	d2.data[2] = 0x329DFB2D;
	d2.data[1] = 0xAE5F7991;
	d2.data[0] = 0xB70077F1;
	cout << "�ͻ���A����ԿdΪ�� " << endl;
	//16������ʽ��ʾ
	d2.display();
	cout << endl;

	cout<<"AES�Ự��ԿΪ��";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", key1[i]);
	}
	cout<<endl;

	/*
	AES aes1(key1,_128BIT);
	byte c1[16];
	char m0[16] ;
	cin>>m0;
	byte *m1 =new byte[16];
	StringToHex(m0,m1);
	cout<<"ת��Ϊ16���ƣ�";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", m1[i]);
	}
	cout<<endl;
	byte m_1[16];

	aes1.encrypt(m1,c1);
	cout<<"���ܺ�õ�����Ϊ��";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", c1[i]);
	}
	cout<<endl;
	for(int i = 0; i < 16; i++){
		cout<<(bitset<8>)c1[i];
	}
	cout<<endl;

	aes1.decrypt(c1,m_1);
	cout<<"���ܺ�õ�����Ϊ��";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", m_1[i]);
	}
	cout<<endl;
	char c0[16];
	HexToString(c0,m_1);
	cout<<c0<<endl;
	*/


	cout << "���ķ���m ��AES�Ự��Կ��" << endl;
	BigInt m;
	m.data[3]= 0x00012001;
	m.data[2] = 0x710198ae;
	m.data[1] = 0xda791714;
	m.data[0] = 0x60153594;
	cout << "���ķ���mΪ��" << endl;
	//16������ʽ��ʾ
	m.display();
	cout << endl;

	cout << "�÷����B�Ĺ���Կe��m����,�õ����ķ���c " << endl;
	BigInt c = PowerMode(m, e1, n1);
	cout << "���ķ���cΪ��" << endl;
	//16������ʽ��ʾ
	c.display();
	cout << endl;
	for(int i = 0; i < 32; i++){
		sprintf(buffer+i*8,"%x", c.data[i]);
	}

		WSADATA wsaData; //��ű�WSAStartup�������ú󷵻ص�Windows Sockets���ݵ����ݽṹ  
	    WSAStartup(MAKEWORD(2, 2), &wsaData);//����ʹ��socket2.2�汾  
	    //�����׽���  
	    SOCKET ClientSocket;  
	    //��ַ����ΪAD_INET����������Ϊ��ʽ(SOCK_STREAM)��Э�����TCP  
	    ClientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);  
		if (ClientSocket == INVALID_SOCKET)  
	    {  
	        cout << "�׽��ִ���ʧ��";  
			WSACleanup();  
	        return 0;  
	    }   
		SOCKADDR_IN ServerAddr;  
	    ServerAddr.sin_family = AF_INET;     //ָ��IP��ʽ  
	    USHORT uPort = 8888;                 //�����������˿�  
	    ServerAddr.sin_port = htons(uPort);   //�󶨶˿ں�  
	    ServerAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");  
	    char client_name[32] = { 0 };  
	    cout << "������������֣�";  
	    cin.getline( client_name,32);  
		connect(ClientSocket, (SOCKADDR*)&ServerAddr, sizeof(ServerAddr));  
	    cout << "���ӳɹ�" << endl;  
	  
	    /*�ȴ�����*/    
	    /*ͨ�����������ӽ���ͨ��*/  
	    //���ͺͽ��ܿͻ��������˵�����  
	    selen = send(ClientSocket, client_name, strlen(client_name), 0);  
	    relen = recv(ClientSocket, server_name, sizeof(server_name), 0); 
		cout<<"�������˷���RSA��Կ���ܺ��AES�Ự��Կ��"<<endl;
		selen = send(ClientSocket, buffer, 256, 0); 

		//����������Ϣ�߳�
	    CloseHandle(CreateThread(NULL, NULL, receiveThread, (LPVOID)&ClientSocket, 0, 0));
		//������Ϣ�����߳�
	    while (1) {  
	           memset(buffer, 0, sizeof(buffer));
			   char m[20] = {0};
	           cin.getline(m,20);  
			   cout << "��"<<client_name << "��: "<<m<<endl; 

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

	         if (strcmp(m, "exit") == 0)  
	         {  
				selen = send(ClientSocket, buffer, sizeof(buffer), 0);  
	            cout << "������3����˳�" << endl;  
				Sleep(3000);  
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
	while (1) {  
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
	    cout <<"��"<< server_name << "��: ";  
	    cout << buffer << endl;  
		cout<<endl;
	} 
}