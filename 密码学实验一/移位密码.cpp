#include<iostream>
#include<stdlib.h>
#include<string>
using namespace std;
char* encryption(char *m , int m_strength){
	char *s = new char[m_strength + 1];
	int i;
	for( i = 0; i < m_strength; i ++ ){
		if(( m[i] >= 65 && m[i] <= 90 ) || ( m[i] >= 97 && m[i] <= 122 ) ){
			if( m[i] + 5 > 90 && m[i] + 5 < 97 ){
				s[i] = 65 + m[i] + 4 - 90;
			}
			else if( m[i] + 5 > 122 ){
				s[i] = 97 + m[i] + 4 - 122;
			}
			else{
				s[i] = m[i] + 5;
			}
		}		
		else
			s[i] = m[i];
	}
	s[i] = m[i];
	return s;
}
char* decode(char *s,int s_strength){
	char *m = new char[s_strength + 1];
	int i;
	for( i = 0 ; i < s_strength ; i ++ ){
		if(( s[i] >= 65 && s[i] <= 90 ) || ( s[i] >= 97 && s[i] <= 122 ) ){
			if( s[i] - 5 < 97 && s[i] - 5 > 90 ){
				m[i] = 122 + s[i] - 4 - 97;
			}
			else if( s[i] - 5 < 65 ){
				m[i] = 90 + s[i] - 4 - 65;
			}
			else{
				m[i] = s[i] - 5;
			}
		}		
		else
			m[i] = s[i];
	}
	m[i] = s[i];
	return m;
}
int main(){
	char *m = "What a smart girl you are";
	char *s;
	int m_strength = strlen(m);
	s = encryption(m,m_strength);
	cout<<"明文长度："<<m_strength<<endl;
	cout<<"明文为："<<"What a smart girl you are"<<endl;
	cout<<"加密后密文为："<<s<<endl;
	int s_strength = strlen(s);
	char *dm = decode(s,s_strength);
	cout<<"密文解密后明文为："<<dm<<endl;
	system("pause");
	return 0;
}
