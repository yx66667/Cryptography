#include<iostream>
#include<stdlib.h>
using namespace std;
int num[26] = {0};
int main() {
	string s = "SIC GCBSPNA XPMHACQ JB GPYXSMEPNXIY JR SINS MF SPNBRQJSSJBE JBFMPQNSJMB FPMQ N XMJBS N SM N XMJBS H HY QCNBR MF N XMRRJHAY JBRCGZPC GINBBCA JB RZGI N VNY SINS SIC MPJEJBNA QCRRNEC GNB MBAY HC PCGMTCPCD HY SIC PJEISFZA PCGJXJCBSR SIC XNPSJGJXNBSR JB SIC SPNBRNGSJMB NPC NAJGC SIC MPJEJBNSMP MF SIC QCRRNEC HMH SIC PCGCJTCP NBD MRGNP N XMRRJHAC MXXMBCBS VIM VJRICR SM ENJB ZBNZSIMPJOCD GMBSPMA MF SIC QCRRNEC";
	int len = s.length();
	string t = s;
	cout<<"字符串长度： "<<len<<endl;
	int total = 0;
	int index;
	for( int i = 0 ; i < len ; i ++ ){
		if( s[i] >= 65 && s[i] <= 90 ){
			total ++;
			index = s[i] - 65;
			num[index] ++;
			if(s[i] == 'A') t[i] = 'L';
			else if (s[i] == 'B') t[i] = 'N';
			else if (s[i] == 'C') t[i] = 'E';
			else if (s[i] == 'E') t[i] = 'G';
			else if (s[i] == 'G') t[i] = 'C';
			else if (s[i] == 'H') t[i] = 'B';
			else if (s[i] == 'I') t[i] = 'H';
			else if (s[i] == 'J') t[i] = 'I';
			else if (s[i] == 'M') t[i] = 'O';
			else if (s[i] == 'N') t[i] = 'A';
			else if (s[i] == 'O') t[i] = 'Z';
			else if (s[i] == 'P') t[i] = 'R';
			else if (s[i] == 'Q') t[i] = 'M';
			else if (s[i] == 'R') t[i] = 'S';
			else if (s[i] == 'S') t[i] = 'T';
			else if (s[i] == 'T') t[i] = 'V';
			else if (s[i] == 'V') t[i] = 'W';
			else if (s[i] == 'X') t[i] = 'P';
			else if (s[i] == 'Z') t[i] = 'U';
			else t[i] = s[i];
		}
	}
	char temp[26];
	for( int i = 0 ; i < 26 ; i ++ ){
		temp[i] = 'A'+i;
	}
	for( int i = 0 ; i < 26 ; i ++ ){
		for(int j = 0 ; j < 25 ; j ++){
			if( num[j] < num[j+1]){
				int temp1 = num[j];
				num[j] = num[j+1];
				num[j+1] = temp1;
				char temp2 = temp[j];
				temp[j] = temp[j+1];
				temp[j+1] = temp2;
			}
		}
	}
	for(int i = 0 ; i < 26 ; i ++ ){
		cout<<temp[i]<<": "<<num[i]<<endl;
	}
	cout<<"字母总数为: "<<total<<endl;
	for( int i = 0; i < len ; i++ ) {
		cout<<t[i];
	}
	system("pause");
	return 0;
}