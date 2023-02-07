#include<iostream>
#include<stdlib.h>
#include<string>
using namespace std;
char initial[26] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'};
char encrypt[26] = {'y','o','u','a','r','e','s','p','m','n','b','c','d','f','g','h','i','j','k','l','q','t','v','w','x','z'};
char* encryption(char *m, int m_strength){
	char *s = new char[m_strength +1];
	int i;
	for( i = 0 ; i < m_strength ; i ++ ){
		if( m[i] >= 97 && m[i] <=122 ){
			int index;
			for( index = 0; index < 26; index++ ){
				if(m[i] == initial[index]) break;
			}
			s[i] = encrypt[index];
		}
		else if( m[i] >=65 && m[i] <=90 ){
			int index;
			for( index = 0; index < 26; index++ ){
				if( m[i] == (initial[index] - 32) ) break;
			}
			s[i] = encrypt[index] - 32;
		}
		else s[i] = m[i];
	}
	s[i] = m[i];
	return s;
}
char* decode(char *s,int s_strength){
    char *m = new char[s_strength +1];
	int i;
	for( i = 0 ; i < s_strength ; i ++ ){
		if( s[i] >= 97 && s[i] <=122 ){
			int index;
			for( index = 0; index < 26; index++ ){
				if(s[i] == encrypt[index]) break;
			}
			m[i] = initial[index];
		}
		else if( s[i] >=65 && s[i] <=90 ){
			int index;
			for( index = 0; index < 26; index++ ){
				if( s[i] == (encrypt[index] - 32) ) break;
			}
			m[i] = initial[index] - 32;
		}
		else m[i] = s[i];
	}
	m[i] = s[i];
	return m;
}
int main(){
	char *m = "WHAT a smart girl you are";
	int m_strength = strlen(m);
	char *s = encryption(m,m_strength);
	cout<<"明文为："<<"WHAT a smart girl you are"<<endl;
	cout<<"加密后密文为："<<s<<endl;
	int s_strength = strlen(s);
	char *dm = decode(s,s_strength);
	cout<<"解密后明文为："<<dm<<endl;
	system("pause");
	return 0;
}