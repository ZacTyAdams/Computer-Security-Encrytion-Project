#include "final.h"

void encryption::execution(){ //Main function that handles user input and encryption function calls
	string input1, input2, output; //inputs used for file names
	cout<<"Enter the name of the input plaintext file: ";
	cin>>input1;
	cout<<"Enther the name of the input key file: "; 
	cin>>input2;
	cout<<"Enter the name of the output ciphertext file: ";
	cin>>output;

	//input1="input.txt";
	//input2="key.txt";
	//output="output.txt";
	
	outputfile.open(output); //initial opening of output file

	string temp;
	int x;	
	

	in.open(input1); //reading input string
	while(!in.eof()){
		getline(in,temp);
		inString += temp;
	}
	in.close();

	if(inString.length() <= 80){ //may not be needed
		for(int i = 0; i < inString.length(); i++){
			if((int)inString[i]>=97 && (int)inString[i]<=122){ //checking to see if all uppercase and under 80 characters
				cout<<"lowercase letters detected"<<endl;
				x++;
				break;
			}
		}
	}
	else{
		cout<<"more than 80 characters detected"<<endl;
	}


	k.open(input2);// reading in the key from key file
	while(!k.eof()){
		getline(k, inKey);
	}
	k.close();

	preprocessing(input1, input2); //calling preprocessing function
	substitution(); //calling substition function
	padding(); //calling padding function
	shiftRows(); //calling shiftrows function
	parityBit(); //calling parityBit function
	mixColumns(); //calling mixColumns function
	outputfile.close(); //closing the output.txt file
}

void encryption::preprocessing(string input, string key){ //preprocessing encryption function to remove punctuation and spaces
	remove_copy_if(inString.begin(), inString.end(), back_inserter(preprop), not1(ptr_fun(&(::isalpha)))); //function used to detect and remove punctuation and spaces
	cout<<"Preprocessing: "<<endl;
	
	outputfile<<"Preprocessing: "<<endl;
	outputfile<<preprop<<endl<<endl;
	
	cout<<preprop<<endl<<endl;

}

void encryption::substitution(){ //substitution encryction function using poly alphabetic substituion 
	int counter=0, shifting, ascii, eascii;
	string temp;
	for(int i = 0; i<preprop.length(); i++){
		if(counter<16){
			shifting = inKey[counter] - 65; //using the key as Vigenere cipher
			ascii = toascii(preprop[i]) - 65;
			eascii = ((ascii+shifting)%26)+65;
			temp+=eascii;
			counter++;
			if(counter == 16){
				counter = 0;
			}
		}
	}
	preprop = temp;
	cout<<"Substitution:"<<endl;

	outputfile<<"Substitution: "<<endl;
	outputfile<<preprop<<endl<<endl;

	cout<<preprop<<endl<<endl;
}

void encryption::padding(){ // padding encryption function, pads bloods according to AES standard
	int space = 0, counter;
	string temp = preprop;

	if(preprop.length()%16!=0){ //calculating when to pad
		counter = (16-temp.length()%16)+temp.length();
	}
	else{
		counter = temp.length();
	}

	for(int i=0; i<counter; i++){
		if(temp[i] == '\0'){
			temp += 'A'; //padding occuring
		}
	}
	cout<<"Padding:"<<endl;
	outputfile<<"Padding: "<<endl;

	preprop = temp;

	for(int i=0; i<counter; i+=4){
		if(space==4){
			cout<<endl; //formatting space between blocks
			outputfile<<endl;
			space=0;
		}
		cout<< preprop[i] << preprop[i+1] << preprop[i+2] << preprop[i+3] << endl;
		outputfile<< preprop[i] << preprop[i+1] << preprop[i+2] << preprop[i+3] << endl;
		space++;
	}

}

void encryption::shiftRows(){ //shiftRow encryption function, Circularly shifts rows in each block a per AES standard
	int counter = 0, space = 0;
	string temp,temp2,tempfinal;
	
	cout<<endl<<"ShiftRows:"<<endl;
	outputfile<<endl<<"ShiftRows:"<<endl;
	for (int i = 0; i < preprop.length(); i++){
		temp += preprop[i]; //reusing
		
		if ((i+1)%4 == 0){
			
			if (counter<4){	
				rotate(temp.begin(),temp.begin() + counter, temp.end()); //rotation function library call
				counter++;
				if (counter == 4){
					counter = 0;
				}
			}
			tempfinal += temp;
			cout<<temp<< endl;	
			outputfile<<temp<< endl;	
			space++;
			temp.clear(); //DO NOT REMOVE WILL CAUSE SEGFAULT
			if(space == 4){ //block spacing
				cout<<endl;
				outputfile<<endl;
				space = 0;
			}
		}	
	}	
	preprop = tempfinal;
}

void encryption::parityBit(){ //parityBit encryption function bit setting based on even or odd then transfer to hex
	cout <<"Parity Bit: "<< endl;
	outputfile<<"Parity Bit: "<<endl;
	
	text = new unsigned char[preprop.length()];
	
	for(int i=0; i<preprop.length(); i++)
		text[i] = preprop[i];
	
	for(int i=0; i<preprop.length(); i++){
		
		bitset<8> parityBit(text[i]);
		
		if(parityBit.count() % 2 !=0) //determin even or od
			parityBit.set(7,1);
		
		text[i] = parityBit.to_ulong();
	
		cout << hex << (int)text[i] << " ";//printing in hex
		outputfile << hex << (int)text[i] << " ";
		
		if( (i+1) % 4 == 0 ){
			cout << endl; //keeping 4 grouping
			outputfile << endl;
		}
	}
	
	cout<<endl;
	outputfile<<endl;
}	


unsigned char encryption::rgfMul(unsigned char x, int mult){ //helper function rgfMul performing Rijndael's Galois field multiplication to be used later
	unsigned char ans;
	
	bitset<8> testBit(x);
	
	if (mult == 2)
	{	
		ans = x << 1;
	}
	else
	{	
		ans = (x<<1) ^ x;
	}	
	
	if(testBit.test(7) == true) ans = ans ^ 27;
	
	return ans;
}

unsigned char encryption::xorstr(unsigned char a,unsigned char b, unsigned char c, unsigned char d){	//helperfunction to perform xor operation addition for rgf
	unsigned char ans = a ^ b ^ c ^ d;
	return ans;
	
}

void encryption::mixColumns(){ //mixcolumns  encryption function follows AES standard by performing circulant mds matrix multiplication with each column
	int j = 0, counter = 0;
	unsigned char a, b, c, d;
	
	for(int x = 0; x < hexVal.size(); x++){
		rgf.push_back(-1);
	}
	for(int i=0; i < preprop.length(); i++)
	{
		a = xorstr(rgfMul(text[i],2),rgfMul(text[i + 4],3),text[i + 8], text[i + 12]);//a0
		b = xorstr(text[i],rgfMul(text[i + 4],2),rgfMul(text[i + 8],3), text[i + 12]);//a1
		c = xorstr(text[i],text[i + 4],rgfMul(text[i + 8],2), rgfMul(text[i + 12],3));//a2		  
		d = xorstr(rgfMul(text[i],3),text[i + 4],text[i + 8], rgfMul(text[i + 12],2));//a3
	
		text[i] = a; text[i+4] = b; text[i+8] = c; text[i+12] = d;
		
		if (counter == 3)
		{	
			counter = 0;
			i += 12;
		}
		else
		{	
			counter++;
		}	
	}
	cout << "MixColumns: " << endl;
	outputfile << "MixColumns: " << endl;
	for(int i=0; i < preprop.length(); i++)
	{	
		cout << hex << (int)text[i]<<" ";
		outputfile << hex << (int)text[i]<<" ";
		if( (i+1) % 4 == 0 ){
			cout<<endl;
			outputfile<<endl;
		}
	}
}

int main(){
	encryption *run = new encryption;
	run->execution(); //executions of prog
	return 0;
}
