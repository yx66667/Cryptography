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
void StringToHex(char *str, byte *strhex) { //每16个字节为1组，变成16进制，不足16个字节的补0x00
	int i,cnt=0;
	char *p = str;             //直针p初始化为指向str
	int len = strlen(str); //获取字符串中的字符个数
	
	while(*p != '\0') {        //结束符判断
		for (i = 0; i < len; i++)  //循环判断当前字符是数字还是小写字符还是大写字母
		{
			if ((*p >= '0') && (*p <= '9')) //当前字符为数字0~9时
				strhex[cnt] = *p - '0' + 0x30;//转为十六进制
			
			if ((*p >= 'A') && (*p <= 'Z')) //当前字符为大写字母A~Z时
				strhex[cnt] = *p - 'A' + 0x41;//转为十六进制
			
			if ((*p >= 'a') && (*p <= 'z')) //当前字符为小写字母a~z时
				strhex[cnt] = *p - 'a' + 0x61;  //转为十六进制
		
			p++;    //指向下一个字符
			cnt++;  
		}
	}
	if(len<16){
		for(cnt;cnt<16;cnt++){
			strhex[cnt] = 0x00;
		}
	}
}
void HexToString(char *str, byte *strhex) { //转化为16个字节的字符串，如果末尾是0x00，则截止
	int i;
	for (i = 0; i < 16; i++) {
		if(strhex[i] == 0x00){
			str[i] = '\0';
			break;
		}
		if(strhex[i]>=0x30 && strhex[i]<=0x39){
			str[i] = strhex[i] - 0x30 + '0';
		}
		if(strhex[i]>=0x41 && strhex[i]<=0x5A){
			str[i] = strhex[i] - 0x41 + 'A';
		}
		if(strhex[i]>=0x61 && strhex[i]<=0x7A){
			str[i] = strhex[i] - 0x61 + 'a';
		}
	}
}

