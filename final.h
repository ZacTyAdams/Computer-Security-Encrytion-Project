#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <bitset>
#include <cmath>


using namespace std;

class encryption{
public:
	void execution();
	void preprocessing(string, string);
	void substitution();
	void padding();
	void shiftRows();
	void parityBit();
	void mixColumns();

	unsigned char rgfMul(unsigned char,int);
	unsigned char xorstr(unsigned char,unsigned char,unsigned char,unsigned char);


	fstream in;
	fstream k;
	ofstream outputfile;
	string output;
	string inString;
	string inKey;
	string preprop;
	unsigned char *text;
	vector<unsigned char> pos;
	vector<string> hexVal;
	vector<unsigned char> rgf;
};
