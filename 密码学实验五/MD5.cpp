#include <iostream>
#include <string>
#include<bitset>
#include<stdlib.h>
using namespace std;
//С��ģʽ
#define A 0x67452301
#define B 0xefcdab89
#define C 0x98badcfe
#define D 0x10325476
//��ת����
#define F(b, c, d) ((b & c) | ((~b) & d))
#define G(b, c, d) ((b & d) | (c & (~d)))
#define H(b, c, d) (b ^ c ^ d)
#define I(b, c, d) (c ^ (b | (~d)))

unsigned int A1;
unsigned int B1;
unsigned int C1;
unsigned int D1;
//T��
const unsigned int T[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
    0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
    0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,
    0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,
    0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
    0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,
    0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,
    0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
    0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};
//s��
const unsigned int S[64] = {
	7 ,12,17,22,7 ,12,17,22,7 ,12,17,22,7 ,12,17,22,
	5 ,9 ,14,20,5 ,9 ,14,20,5 ,9 ,14,20,5 ,9 ,14,20,
	4 ,11,16,23,4 ,11,16,23,4 ,11,16,23,4 ,11,16,23,
	6 ,10,15,21,6 ,10,15,21,6 ,10,15,21,6 ,10,15,21
};

string hexToStr(unsigned int hexNum) { //16������ת�ַ������������
    string x = "0123456789abcdef";
    string res = "";
    string temp = "";
    for(int i = 0; i < 8; ++i) {
        unsigned int index = hexNum>>(i*4) & 0xf;
        temp += x[index];
        if((i+1) % 2 == 0) {
            reverse(temp.begin(), temp.end());
            res += temp;
            temp = "";
        }
    }
    return res;
}
int groupNum;//��������
//���ԭ��
unsigned int *padding(string Text) { 
	//x + 64 / 512 + 1�������֮��512������
	groupNum = (Text.length()+8) / 64 + 1; //��������������ֽ�Ϊ��λ��512λ = 64 char��>=512λʱ�����1��<512ʱ���鲻��
	unsigned int * res = new unsigned int[groupNum * 16];
	int i;
	for(i = 0; i < groupNum * 16; i++) {
		res[i] = 0;	//��ʼ��ȫ��0
	}
	int temp = 0; //��ԭ������Ϣ�����������ַ�������int��
	for(i = 0; i < Text.length(); i++) {
		res[temp] |=  (Text[i] << ((i%4)*8));
		if((i+1) % 4 == 0) temp++;
	}
	res[temp] |= 0x80 << ((i%4)*8);	//β����1��1000 0000

	res[groupNum*16 - 2] = Text.length() * 8; //��64λ������Ϣ�ĳ��ȣ�ֻ���õ�32λ
	return res;
}

unsigned int LeftShift(unsigned int content, unsigned int offset) { //����
	unsigned int res = content << offset;
	res |= content >> (32 - offset);
	return res;
}

void Hmd5(unsigned int *mes) {
	unsigned int a = A1; //�ȸ��ϳ�ֵ
	unsigned int b = B1;
	unsigned int c = C1;
	unsigned int d = D1;
	unsigned int f,k;
	for(int i = 0; i < 64; i++) { //����4���֣�64С�ֵ�����
		if(i < 16) {	
			f = F(b,c,d);
			k = i;
		}
		else if(i < 32) {
			f = G(b,c,d);
			k = (5*i + 1) % 16;
		}
		else if(i < 48) {
			f = H(b,c,d);
			k = (3 * i + 5) % 16;
		}
		else if(i < 64) {
			f = I(b,c,d);
			k = (7 * i) % 16;
		}

		unsigned int t = b + LeftShift(a + f + mes[k] + T[i], S[i]); //��λ����

		unsigned int temp = d; //������ɺ�����ĸ���֮��Ľ���
		d = c;
		c = b;
		b = t;
		a = temp;
	}
	//����������Ҫ���ϳ�ֵ
	A1 += a;
	B1 += b;
	C1 += c;
	D1 += d;
}

string MD5(string message) {
	A1=A;    //��ʼ��
    B1=B;
    C1=C;
    D1=D;
	unsigned int * Mes = padding(message);
	//���飬����ÿ512λ����Ҫ����һ��64�ֵ�����
	for(int i = 0; i < groupNum; i++) {
		unsigned int mes[16];
		for(int j = 0; j < 16; j++){
			mes[j] = Mes[i * 16 + j];
		}
		Hmd5(mes);
	}
	string res = hexToStr(A1)+hexToStr(B1)+hexToStr(C1)+hexToStr(D1);//��ABCD������Ȼ����string
	return res;
}


int main() {
	string s;
	string res;

	s="";
	cout<<"test1: "<<s<<endl;
	res = MD5(s);
	cout<<"MD5 message: "<<res<<endl;
	s="a";
	cout<<"test2: "<<s<<endl;
	res = MD5(s);
	cout<<"MD5 message: "<<res<<endl;
	s="abc";
	cout<<"test3: "<<s<<endl;
	res = MD5(s);
	cout<<"MD5 message: "<<res<<endl;
	s="message digest";
	cout<<"test4: "<<s<<endl;
	res = MD5(s);
	cout<<"MD5 message: "<<res<<endl;
	s="abcdefghijklmnopqrstuvwxyz";
	cout<<"test5: "<<s<<endl;
	res = MD5(s);
	cout<<"MD5 message: "<<res<<endl;
	s="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	cout<<"test6: "<<s<<endl;
	res = MD5(s);
	cout<<"MD5 message: "<<res<<endl;
	s="12345678901234567890123456789012345678901234567890123456789012345678901234567890";
	cout<<"test7: "<<s<<endl;
	res = MD5(s);
	cout<<"MD5 message: "<<res<<endl;
	cout<<"test7���תΪ�����ƣ�";
	for(int i = 0; i < 32; i++){
		cout<<(bitset<4>)res[i];
	}
	cout<<endl;

	//��ʼ����ѩ��ЧӦ����
	cout<<"---------------------ѩ��ЧӦ����-------------------------"<<endl;
	string t0 = "01010111010101000110010000010010001000100101001100111001010101010001001101001001010000010010010100100001000001110010011001110001";
	s=" 12345678901234567890123456789012345678901234567890123456789012345678901234567890";
	res = MD5(s);
	cout<<"MD5 message: "<<res<<endl;
	cout<<"���תΪ�����ƣ�";
	for(int i = 0; i < 32; i++){
		cout<<(bitset<4>)res[i];
	}
	cout<<endl;

	s="123,45678901234567890123456789012345678901234567890123456789012345678901234567890";
	res = MD5(s);
	cout<<"MD5 message: "<<res<<endl;
	cout<<"���תΪ�����ƣ�";
	for(int i = 0; i < 32; i++){
		cout<<(bitset<4>)res[i];
	}
	cout<<endl;

	s="1234567890  1234567890123456789012345678901234567890123456789012345678901234567890";
	res = MD5(s);
	cout<<"MD5 message: "<<res<<endl;
	cout<<"���תΪ�����ƣ�";
	for(int i = 0; i < 32; i++){
		cout<<(bitset<4>)res[i];
	}
	cout<<endl;

	s="12345678901234567890!123456789012345678901234567890123456789012345678901234567890";
	res = MD5(s);
	cout<<"MD5 message: "<<res<<endl;
	cout<<"���תΪ�����ƣ�";
	for(int i = 0; i < 32; i++){
		cout<<(bitset<4>)res[i];
	}
	cout<<endl;

	s="1234567890123456789012345678?9012345678901234567890123456789012345678901234567890";
	res = MD5(s);
	cout<<"MD5 message: "<<res<<endl;
	cout<<"���תΪ�����ƣ�";
	for(int i = 0; i < 32; i++){
		cout<<(bitset<4>)res[i];
	}
	cout<<endl;

	s="12345678901234567890123456789012+345678901234567890123456789012345678901234567890";
	res = MD5(s);
	cout<<"MD5 message: "<<res<<endl;
	cout<<"���תΪ�����ƣ�";
	for(int i = 0; i < 32; i++){
		cout<<(bitset<4>)res[i];
	}
	cout<<endl;

	s="123456789012345678901234567890123456789012345678901234567,89012345678901234567890";
	res = MD5(s);
	cout<<"MD5 message: "<<res<<endl;
	cout<<"���תΪ�����ƣ�";
	for(int i = 0; i < 32; i++){
		cout<<(bitset<4>)res[i];
	}
	cout<<endl;

	s="123,45678901234567890123456789012345678901234567890123456789012345678901234567890.";
	res = MD5(s);
	cout<<"MD5 message: "<<res<<endl;
	cout<<"���תΪ�����ƣ�";
	for(int i = 0; i < 32; i++){
		cout<<(bitset<4>)res[i];
	}
	cout<<endl;	
	string t1 = "01101001100010000001000001001000001001000000000000010100011100100001011001010001010100010100000101001001010001101001010010000110";
	string t2 = "00010100010101000101011000000011100001000000000101001000100010010001001110010100000110000011001101100100010101010011010100010101";
	string t3 = "01000010010101110101000010000101001101000110011001010101010000000100000101110011000010010011001001000111011001010001010001100011";
	string t4 = "00010000011001010100001001010001001100010100011001110100001000110010001100110010001000100011100000100101010000100010010000010110";
	string t5 = "00100110000100010001010110010011010001001001001010001000011000100011011100100101001000110010010100110101011001010010010101010010";
	string t6 = "00101000100001010110010000010101001100100110011000010001001001100001010101000010100100100110001101100010010001101001000000100110";
	string t7 = "01100101011001010110011010000000010001110001001010000000010001100110100000110100010100111001100010010100010100101001100100110110";
	string t8 = "01100101011101001001011100110100001100100001010001011000011001000011011000000110100101100101010101010010011110000111011001101001";
	double sum = 0;
	int temp = 0;
	for(int i = 0; i <128; i++){
		if(t0[i]!=t1[i])
			temp++;
	}
	cout<<"�У�"<<temp<<"λ��ͬ"<<endl;
	sum +=temp;

	temp = 0;
	for(int i = 0; i <128; i++){
		if(t0[i]!=t2[i])
			temp++;
	}
	cout<<"�У�"<<temp<<"λ��ͬ"<<endl;
	sum +=temp;

	temp = 0;
	for(int i = 0; i <128; i++){
		if(t0[i]!=t3[i])
			temp++;
	}
	cout<<"�У�"<<temp<<"λ��ͬ"<<endl;
	sum +=temp;

	temp = 0;
	for(int i = 0; i <128; i++){
		if(t0[i]!=t4[i])
			temp++;
	}
	cout<<"�У�"<<temp<<"λ��ͬ"<<endl;
	sum +=temp;

	temp = 0;
	for(int i = 0; i <128; i++){
		if(t0[i]!=t5[i])
			temp++;
	}
	cout<<"�У�"<<temp<<"λ��ͬ"<<endl;
	sum +=temp;

	temp = 0;
	for(int i = 0; i <128; i++){
		if(t0[i]!=t6[i])
			temp++;
	}
	cout<<"�У�"<<temp<<"λ��ͬ"<<endl;
	sum +=temp;

	temp = 0;
	for(int i = 0; i <128; i++){
		if(t0[i]!=t7[i])
			temp++;
	}
	cout<<"�У�"<<temp<<"λ��ͬ"<<endl;
	sum +=temp;

	temp = 0;
	for(int i = 0; i <128; i++){
		if(t0[i]!=t8[i])
			temp++;
	}
	cout<<"�У�"<<temp<<"λ��ͬ"<<endl;
	sum +=temp;
	cout<<"ƽ���ı��ˣ�"<<sum/8<<endl;
		
	system("pause");
	return 0;

}