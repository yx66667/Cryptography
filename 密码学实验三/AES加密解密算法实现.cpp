#include<iostream>
#include <string.h>
#include<bitset>
#include <stdio.h>
using namespace std;
typedef unsigned char byte;

//128bit 196bit 256bit
enum LENGTH  
{
    _128BIT, _196BIT, _256BIT
};
class AES{
public:
    AES(const byte key[],enum LENGTH keyBits);
	virtual ~AES(){};
    void encrypt(const byte data[16], byte out[16]);
    void decrypt(const byte data[16], byte out[16]);

private:
    int Nb; //明文分组
    int Nk; //密钥分组
    int Nr; //加密轮数
    byte Key[32]; //初始密钥
    byte W[60][4]; //扩展密钥
    static byte sBox[]; //S盒
    static byte invSBox[]; //逆S盒 
    static byte Rcon[]; //常数
    void setKey(const byte key[], const int keyBits);

    void byteSub(byte state[][4]);  //加密过程中的轮函数
    void shiftRows(byte state[][4]);
    void mixColumns(byte state[][4]);
    void addRoundKey(byte state[][4], byte w[][4]);

    void invByteSub(byte state[][4]); //解密过程中的轮函数
    void invShiftRows(byte state[][4]);
    void invMixColumns(byte state[][4]);

    void keyExpansion(); //密钥扩展函数
	void getKey(byte key[][4],int i);
    byte GF28Multi(byte s, byte a);   //计算GF（2的8次方）下的乘法
    void rotByte(byte w[]);
    void subByte(byte w[]);

};

byte AES::sBox[] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  
};
byte AES::invSBox[] = { 
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d 
};

byte AES::Rcon[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

AES::AES(const byte key[],enum LENGTH keyBytes){
    int keyBits;
    if (keyBytes == LENGTH::_128BIT){
        keyBits = 128;
    }
    else if (keyBytes==LENGTH::_196BIT){
        keyBits = 192;
    }
    else if (keyBytes==LENGTH::_256BIT){
        keyBits = 256;
    }
    setKey(key,keyBits);
    keyExpansion();
}

void AES::setKey(const byte key[], const int keyBits){ //AES明文分组长度为4，密钥长度为128bit时，密钥分组为4，加密轮数为10
	                                                   //密钥长度为196bit时，密钥分组为6，加密轮数为12
    Nb = 4;                                            //密钥长度为256bit时，密钥分组为8，加密轮数为14
    if (keyBits == 128){
        Nk = 4;
        Nr = 10;
    }else if (keyBits == 192){
        Nk = 6;
        Nr = 12;
    }else if (keyBits == 256){
        Nk = 8;
        Nr = 14;
    }
    memcpy(Key,key,Nk*4);
}
//密钥编排部分函数
void AES::rotByte(byte w[]) //循环向左移动一位
{
    byte temp = w[0];
	for(int i = 0; i < 3; i++){
		w[i] = w[i+1];
	}
    w[3] = temp;
}

void AES::subByte(byte w[]) //s盒代换
{
    for (int i = 0; i < 4; i++){
        w[i] = sBox[w[i]];
    }
}
//密钥扩展函数
void AES::keyExpansion(){
    for (int i = 0; i < Nk; i++){
        for (int j = 0; j < 4; j++){ //前Nk个字照抄
            W[i][j] = Key[j+i*4];
        }
    }
    for (int i = Nk; i < Nb*(Nr + 1); i++){ //进行扩展密钥
        byte pre_w[4]; //取前一个字
        for (int k = 0; k < 4; k++){
            pre_w[k] = W[i-1][k];
        }
        if(i%Nk == 0){
            rotByte(pre_w);
            subByte(pre_w);
            pre_w[0] ^= Rcon[i / Nk - 1]; //由于和0异或为自身因此仅异或第一个字节
        }else if ((Nk>6)&&(i%Nk==4)){ //当Nk>6时还要再进行一次S盒代换
            subByte(pre_w);
        }else{
		}
        for (int k = 0; k < 4; k++){ //前一个和前第Nk个异或
            W[i][k] = pre_w[k] ^ W[i-Nk][k];
        }
    }
}

void AES::byteSub(byte state[][4])  //S盒代换
{
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            state[i][j] = sBox[state[i][j]];
        }
    }
}
void AES::shiftRows(byte state[][4]) //行移位
{
    byte t[4];
    for (int i = 1; i < 4; i++){
        for (int j = 0; j < 4; j++){
            t[j] = state[i][(i + j) % 4];
        }
        for (int j = 0; j < 4; j++){
            state[i][j] = t[j];
        }
    }
}

void AES::mixColumns(byte state[][4]) //列混合
{
    byte t[4];
    for (int j = 0; j < 4; j++){
        for (int i = 0; i < 4; i++){
            t[i] = state[i][j];
        }
        for (int i = 0; i < 4; i++){
            state[i][j] = GF28Multi(t[i], 0x02)^GF28Multi(t[(i + 1) % 4], 0x03)^GF28Multi(t[(i + 2) % 4], 0x01)^GF28Multi(t[(i + 3) % 4], 0x01);
        }
    }
}

void AES::addRoundKey(byte state[][4], byte w[][4])  //密钥加
{
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            state[i][j] ^= w[i][j];
        }
    }
}

void AES::invByteSub(byte state[][4]) //逆字节代换
{
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            state[i][j] = invSBox[state[i][j]];
        }
    }
}

void AES::invShiftRows(byte state[][4]) //逆行移位
{
    byte t[4];
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            t[j] = state[i][(j-i + 4) % 4];
        }
        for (int j = 0; j < 4; j++){
            state[i][j] = t[j];
        }
    }
}

void AES::invMixColumns(byte state[][4]) //逆列混合
{
    byte t[4];
    for (int j = 0; j < 4; j++){
        for (int i = 0; i < 4; i++){
            t[i] = state[i][j];
        }
        for (int i = 0; i < 4; i++){
            state[i][j] = GF28Multi(t[i], 0x0e)^GF28Multi(t[(i+1)%4],0x0b)^GF28Multi(t[(i+2)%4],0x0d)^GF28Multi(t[(i+3)%4],0x09);
        }
    }
}

//计算GF（2的8次方）下的乘法
byte AES::GF28Multi(byte s,byte a){
    byte t[4];
    byte result = 0;
    t[0] = s;
    for (int i = 1; i < 4; i++){
        t[i] = t[i - 1] << 1;
        if (t[i - 1] & 0x80){
            t[i] ^= 0x1b;
        }
    }
    for (int i = 0; i < 4; i++){
        if ((a >> i) & 0x01){
            result ^= t[i];
        }
    }
    return result;
}

void AES::encrypt(const byte data[16], byte out[16]) //加密函数
{
    byte state[4][4];
    byte key[4][4];
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            state[i][j] = data[i+j*4];
        }
    }
    getKey(key, 0);
    addRoundKey(state, key);
    for (int i = 1; i <= Nr; i++){
        byteSub(state);
        shiftRows(state);

        if (i != Nr){
            mixColumns(state);
        }
        getKey(key, i);
        addRoundKey(state, key);
    }

    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            out[i+j*4] = state[i][j];
        }
    }
}

void AES::decrypt(const byte data[16], byte out[16]) //解密函数
{
    byte state[4][4];
    byte key[4][4];
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            state[i][j] = data[i+j*4];
        }
    }
    getKey(key, Nr);
    addRoundKey(state,key);
    for (int i = (Nr - 1); i >= 0; i--){
        invShiftRows(state);
        invByteSub(state);
        getKey(key, i);
        addRoundKey(state,key);
        if (i > 0){
            invMixColumns(state);
        }
    }
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            out[i + j*4] = state[i][j];
        }
    }
}
void AES::getKey(byte key[][4], int index){
    for (int i = index*4; i < index*4+4; i++){
        for (int j = 0; j < 4; j++){
            key[j][i-index*4] = W[i][j];
        }
    }
}

int main(){
	//第一个测试用例
	byte key1[16] = { //初始密钥0001, 2001, 7101, 98ae, da79, 1714, 6015, 3594
        0x00, 0x01, 0x20, 0x01,
        0x71, 0x01, 0x98, 0xae,
        0xda, 0x79, 0x17, 0x14,
        0x60, 0x15, 0x35, 0x94
    };
	cout<<"密钥为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", key1[i]);
	}
	cout<<endl;

	AES aes1(key1,_128BIT);
	byte c1[16];
	byte m1[16] ={0x00,0x01,0x00,0x01,0x01,0xa1,0x98,0xaf,0xda,0x78,0x17,0x34,0x86,0x15,0x35,0x66};
	byte m_1[16];

	aes1.encrypt(m1,c1);
	cout<<"加密后得到的数为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", c1[i]);
	}
	cout<<endl;
	for(int i = 0; i < 16; i++){
		cout<<(bitset<8>)c1[i];
	}
	cout<<endl;

	aes1.decrypt(c1,m_1);
	cout<<"解密后得到的数为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", m_1[i]);
	}
	cout<<endl;
	cout<<"----------------------------------------------------------------"<<endl;
	//第二个测试用例
	byte key2[16] = { //初始密钥2b7e, 1516, 28ae, d2a6, abf7, 1588, 09cf, 4f3c
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };
	cout<<"密钥为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", key2[i]);
	}
	cout<<endl;

	AES aes2(key2,_128BIT);
	byte c2[16]; //3243, f6a8, 885a, 308d, 3131, 98a2, e037, 0734
	byte m2[16] ={0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
	byte m_2[16];

	aes2.encrypt(m2,c2);
	cout<<"加密后得到的数为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", c2[i]);
	}
	cout<<endl;
	for(int i = 0; i < 16; i++){
		cout<<(bitset<8>)c2[i];
	}
	cout<<endl;

	aes2.decrypt(c2,m_2);
	cout<<"解密后得到的数为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", m_2[i]);
	}
	cout<<endl;

	cout<<"----------------------------------------------------------------"<<endl;
	cout<<"针对测试数据做雪崩实验：【1】改变明文"<<endl;
	byte m1_change1[16] ={0x10,0x01,0x00,0x01,0x01,0xa1,0x98,0xaf,0xda,0x78,0x17,0x34,0x86,0x15,0x35,0x66};
	aes1.encrypt(m1_change1,c1);
	cout<<"加密后得到的数为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", c1[i]);
	}
	cout<<endl;
	for(int i = 0; i < 16; i++){
		cout<<(bitset<8>)c1[i];
	}
	cout<<endl;
	byte m1_change2[16] ={0x20,0x01,0x00,0x01,0x01,0xa1,0x98,0xaf,0xda,0x78,0x17,0x34,0x86,0x15,0x35,0x66};
	aes1.encrypt(m1_change2,c1);
	cout<<"加密后得到的数为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", c1[i]);
	}
	cout<<endl;
	for(int i = 0; i < 16; i++){
		cout<<(bitset<8>)c1[i];
	}
	cout<<endl;
	byte m1_change3[16] ={0x40,0x01,0x00,0x01,0x01,0xa1,0x98,0xaf,0xda,0x78,0x17,0x34,0x86,0x15,0x35,0x66};
	aes1.encrypt(m1_change3,c1);
	cout<<"加密后得到的数为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", c1[i]);
	}
	cout<<endl;
	for(int i = 0; i < 16; i++){
		cout<<(bitset<8>)c1[i];
	}
	cout<<endl;
	byte m1_change4[16] ={0x80,0x01,0x00,0x01,0x01,0xa1,0x98,0xaf,0xda,0x78,0x17,0x34,0x86,0x15,0x35,0x66};
	aes1.encrypt(m1_change4,c1);
	cout<<"加密后得到的数为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", c1[i]);
	}
	cout<<endl;
	for(int i = 0; i < 16; i++){
		cout<<(bitset<8>)c1[i];
	}
	cout<<endl;
	byte m1_change5[16] ={0x01,0x01,0x00,0x01,0x01,0xa1,0x98,0xaf,0xda,0x78,0x17,0x34,0x86,0x15,0x35,0x66};
	aes1.encrypt(m1_change5,c1);
	cout<<"加密后得到的数为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", c1[i]);
	}
	cout<<endl;
	for(int i = 0; i < 16; i++){
		cout<<(bitset<8>)c1[i];
	}
	cout<<endl;
	byte m1_change6[16] ={0x02,0x01,0x00,0x01,0x01,0xa1,0x98,0xaf,0xda,0x78,0x17,0x34,0x86,0x15,0x35,0x66};
	aes1.encrypt(m1_change6,c1);
	cout<<"加密后得到的数为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", c1[i]);
	}
	cout<<endl;
	for(int i = 0; i < 16; i++){
		cout<<(bitset<8>)c1[i];
	}
	cout<<endl;
	byte m1_change7[16] ={0x04,0x01,0x00,0x01,0x01,0xa1,0x98,0xaf,0xda,0x78,0x17,0x34,0x86,0x15,0x35,0x66};
	aes1.encrypt(m1_change7,c1);
	cout<<"加密后得到的数为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", c1[i]);
	}
	cout<<endl;
	for(int i = 0; i < 16; i++){
		cout<<(bitset<8>)c1[i];
	}
	cout<<endl;
	byte m1_change8[16] ={0x08,0x01,0x00,0x01,0x01,0xa1,0x98,0xaf,0xda,0x78,0x17,0x34,0x86,0x15,0x35,0x66};
	aes1.encrypt(m1_change8,c1);
	cout<<"加密后得到的数为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", c1[i]);
	}
	cout<<endl;
	for(int i = 0; i < 16; i++){
		cout<<(bitset<8>)c1[i];
	}
	cout<<endl;
	char s0[129] = "01101100110111010101100101101011100011110101011001000010110010111101001000111011010001111001100000011010011001010100001000101010";
	char s1[129] = "11110010100011110110100110000000101110010111000011011011100100000110001111111110000001001011011110011110100101111011100011010111";
	char s2[129] = "00110100011010010000101100011101010110111000010001110101110011111110100001100011100111110010111000111101101100000100011110011011";
	char s3[129] = "00010000110100111001100011100111010101110101010000111010011001110000111000111010010101011110010111100011101101011111100010100100";
	char s4[129] = "00100111101111110011110010001101011111010101111001010100101110110011110111110001111100100011101000100101010111100111010010001111";
	char s5[129] = "00111001110100111110101011011111000011111000011000010011011001010111110010111011110010101100011011101000110011110000010100010100";
	char s6[129] = "01000001110011011011100001101100111100000111100111010000100000001010111000010011000000011011011110100110011000010110110011101100";
	char s7[129] = "10101100001111100000100101010010111111010111001001111101101000100100111010110101100000100011100011110010110000001100000110010000";
	char s8[129] = "00110110011101010111101110000110111101010000001000101010111110010110100001100111001101101000101110111001000101111111100010001101";
	double sum = 0;
	int temp = 0;
	for(int i = 0; i <128; i++){
		if(s0[i]!=s1[i])
			temp++;
	}
	cout<<"有："<<temp<<"位不同"<<endl;
	sum +=temp;

	temp = 0;
	for(int i = 0; i <128; i++){
		if(s0[i]!=s2[i])
			temp++;
	}
	cout<<"有："<<temp<<"位不同"<<endl;
	sum +=temp;

	temp = 0;
	for(int i = 0; i <128; i++){
		if(s0[i]!=s3[i])
			temp++;
	}
	cout<<"有："<<temp<<"位不同"<<endl;
	sum +=temp;

	temp = 0;
	for(int i = 0; i <128; i++){
		if(s0[i]!=s4[i])
			temp++;
	}
	cout<<"有："<<temp<<"位不同"<<endl;
	sum +=temp;

	temp = 0;
	for(int i = 0; i <128; i++){
		if(s0[i]!=s5[i])
			temp++;
	}
	cout<<"有："<<temp<<"位不同"<<endl;
	sum +=temp;

	temp = 0;
	for(int i = 0; i <128; i++){
		if(s0[i]!=s6[i])
			temp++;
	}
	cout<<"有："<<temp<<"位不同"<<endl;
	sum +=temp;

	temp = 0;
	for(int i = 0; i <128; i++){
		if(s0[i]!=s7[i])
			temp++;
	}
	cout<<"有："<<temp<<"位不同"<<endl;
	sum +=temp;

	temp = 0;
	for(int i = 0; i <128; i++){
		if(s0[i]!=s8[i])
			temp++;
	}
	cout<<"有："<<temp<<"位不同"<<endl;
	sum +=temp;
	cout<<"平均改变了："<<sum/8<<endl;

	cout<<"----------------------------------------------------------------"<<endl;
	cout<<"针对测试数据做雪崩实验：【2】改变密钥"<<endl;
	//明文：m1{0x00,0x01,0x00,0x01,0x01,0xa1,0x98,0xaf,0xda,0x78,0x17,0x34,0x86,0x15,0x35,0x66};
	//初始密钥0001, 2001, 7101, 98ae, da79, 1714, 6015, 3594
	byte key1_change1[16] = { 
        0x10, 0x01, 0x20, 0x01,
        0x71, 0x01, 0x98, 0xae,
        0xda, 0x79, 0x17, 0x14,
        0x60, 0x15, 0x35, 0x94
    };
	AES aes_change1(key1_change1,_128BIT);
	aes_change1.encrypt(m1,c1);
	cout<<"加密后得到的数为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", c1[i]);
	}
	cout<<endl;
	for(int i = 0; i < 16; i++){
		cout<<(bitset<8>)c1[i];
	}
	cout<<endl;

	byte key1_change2[16] = { 
        0x20, 0x01, 0x20, 0x01,
        0x71, 0x01, 0x98, 0xae,
        0xda, 0x79, 0x17, 0x14,
        0x60, 0x15, 0x35, 0x94
    };
	AES aes_change2(key1_change2,_128BIT);
	aes_change2.encrypt(m1,c1);
	cout<<"加密后得到的数为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", c1[i]);
	}
	cout<<endl;
	for(int i = 0; i < 16; i++){
		cout<<(bitset<8>)c1[i];
	}
	cout<<endl;

	byte key1_change3[16] = { 
        0x40, 0x01, 0x20, 0x01,
        0x71, 0x01, 0x98, 0xae,
        0xda, 0x79, 0x17, 0x14,
        0x60, 0x15, 0x35, 0x94
    };
	AES aes_change3(key1_change3,_128BIT);
	aes_change3.encrypt(m1,c1);
	cout<<"加密后得到的数为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", c1[i]);
	}
	cout<<endl;
	for(int i = 0; i < 16; i++){
		cout<<(bitset<8>)c1[i];
	}
	cout<<endl;

	byte key1_change4[16] = { 
        0x80, 0x01, 0x20, 0x01,
        0x71, 0x01, 0x98, 0xae,
        0xda, 0x79, 0x17, 0x14,
        0x60, 0x15, 0x35, 0x94
    };
	AES aes_change4(key1_change4,_128BIT);
	aes_change4.encrypt(m1,c1);
	cout<<"加密后得到的数为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", c1[i]);
	}
	cout<<endl;
	for(int i = 0; i < 16; i++){
		cout<<(bitset<8>)c1[i];
	}
	cout<<endl;

	byte key1_change5[16] = { 
        0x01, 0x01, 0x20, 0x01,
        0x71, 0x01, 0x98, 0xae,
        0xda, 0x79, 0x17, 0x14,
        0x60, 0x15, 0x35, 0x94
    };
	AES aes_change5(key1_change5,_128BIT);
	aes_change5.encrypt(m1,c1);
	cout<<"加密后得到的数为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", c1[i]);
	}
	cout<<endl;
	for(int i = 0; i < 16; i++){
		cout<<(bitset<8>)c1[i];
	}
	cout<<endl;

	byte key1_change6[16] = { 
        0x02, 0x01, 0x20, 0x01,
        0x71, 0x01, 0x98, 0xae,
        0xda, 0x79, 0x17, 0x14,
        0x60, 0x15, 0x35, 0x94
    };
	AES aes_change6(key1_change6,_128BIT);
	aes_change6.encrypt(m1,c1);
	cout<<"加密后得到的数为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", c1[i]);
	}
	cout<<endl;
	for(int i = 0; i < 16; i++){
		cout<<(bitset<8>)c1[i];
	}
	cout<<endl;

	byte key1_change7[16] = { 
        0x04, 0x01, 0x20, 0x01,
        0x71, 0x01, 0x98, 0xae,
        0xda, 0x79, 0x17, 0x14,
        0x60, 0x15, 0x35, 0x94
    };
	AES aes_change7(key1_change7,_128BIT);
	aes_change7.encrypt(m1,c1);
	cout<<"加密后得到的数为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", c1[i]);
	}
	cout<<endl;
	for(int i = 0; i < 16; i++){
		cout<<(bitset<8>)c1[i];
	}
	cout<<endl;

	byte key1_change8[16] = { 
        0x08, 0x01, 0x20, 0x01,
        0x71, 0x01, 0x98, 0xae,
        0xda, 0x79, 0x17, 0x14,
        0x60, 0x15, 0x35, 0x94
    };
	AES aes_change8(key1_change8,_128BIT);
	aes_change8.encrypt(m1,c1);
	cout<<"加密后得到的数为：";
	for(int i = 0; i < 16; i++){
		printf("0x%02X ", c1[i]);
	}
	cout<<endl;
	for(int i = 0; i < 16; i++){
		cout<<(bitset<8>)c1[i];
	}
	cout<<endl;

	char t0[129] = "01101100110111010101100101101011100011110101011001000010110010111101001000111011010001111001100000011010011001010100001000101010";
	char t1[129] = "11100100001100011011011011110101010001100000110110100111010010110010000011010110100011000000010101000101100000011011011000001110";
	char t2[129] = "01111101110110000100100010001110111010010000111010111111110001011010000100011100100100111110001010111100000111110011010010011000";
	char t3[129] = "11000001001010001110000001111110011100110101001000111101010011001101010101111011001010111101011110110111111011110011101010111011";
	char t4[129] = "10001101100111101111001101011011011111011000001000111110101001010010111111111010100110001111101000111100110110101110101101000011";
	char t5[129] = "10100111011110100100000111111000111001110010000011000101111110010111101010110111110010000101001100100111001110111010100110000000";
	char t6[129] = "11001110101110010100000010111011100111001000011000100111100010111110101110000110001010001110111000000000100011010010111100001100";
	char t7[129] = "11101110101010010110100111011110100010111100001000110101000010000001111101100010000011100000010110011011110000010000011001011000";
	char t8[129] = "01101110100010001101000001001011111000100000101110010100101010111101101010111100011001010010111000100001111000101000000111110011";
	sum = 0;
	temp = 0;
	for(int i = 0; i <128; i++){
		if(t0[i]!=t1[i])
			temp++;
	}
	cout<<"有："<<temp<<"位不同"<<endl;
	sum +=temp;

	temp = 0;
	for(int i = 0; i <128; i++){
		if(t0[i]!=t2[i])
			temp++;
	}
	cout<<"有："<<temp<<"位不同"<<endl;
	sum +=temp;

	temp = 0;
	for(int i = 0; i <128; i++){
		if(t0[i]!=t3[i])
			temp++;
	}
	cout<<"有："<<temp<<"位不同"<<endl;
	sum +=temp;

	temp = 0;
	for(int i = 0; i <128; i++){
		if(t0[i]!=t4[i])
			temp++;
	}
	cout<<"有："<<temp<<"位不同"<<endl;
	sum +=temp;

	temp = 0;
	for(int i = 0; i <128; i++){
		if(t0[i]!=t5[i])
			temp++;
	}
	cout<<"有："<<temp<<"位不同"<<endl;
	sum +=temp;

	temp = 0;
	for(int i = 0; i <128; i++){
		if(t0[i]!=t6[i])
			temp++;
	}
	cout<<"有："<<temp<<"位不同"<<endl;
	sum +=temp;

	temp = 0;
	for(int i = 0; i <128; i++){
		if(t0[i]!=t7[i])
			temp++;
	}
	cout<<"有："<<temp<<"位不同"<<endl;
	sum +=temp;

	temp = 0;
	for(int i = 0; i <128; i++){
		if(t0[i]!=t8[i])
			temp++;
	}
	cout<<"有："<<temp<<"位不同"<<endl;
	sum +=temp;
	cout<<"平均改变了："<<sum/8<<endl;

	system("pause");
	return 0;
}
