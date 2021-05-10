#include <iostream>
#include <vector>  
#include <string>
#include <utility> 
#include "sha256.h"
#include "BigInt.cpp"
#include <sstream>



using namespace std;

const int targetBits = 24;



struct Block
     {
        int Timestamp;
        int Nonce;
        string Data;
	   string PrevBlockHash;
	   string Hash; 
     };

struct ProofOfWork
{
     Block *block;
     BigInt *target;
      
};

ProofOfWork NewProofOfWork( Block *b) {
	BigInt target = "1";
	target = target << (256-targetBits);
	ProofOfWork pow = ProofOfWork{b, &target};

	return pow;
}

string IntToHex(int decimal_value){
     stringstream ss;
     ss<< hex << decimal_value; // int decimal_value
     string res ( ss.str() );

     return res;
}


vector<string> prepareData(int nonce , ProofOfWork *pow){

     vector<string> data = {{"pow.block.PrevBlockHash",
     "pow.block.Data",
     IntToHex(pow->block->Timestamp),
     IntToHex(targetBits),
     IntToHex(nonce)}, {} };

     return data;
}

pair <int, string> Run(ProofOfWork *pow){
     BigInt hashInt;
     pair <int, string> hashnonce;
     hashnonce.first = 0;

     cout << "Mining the block containing" << pow->block->Data << endl;

     while (hashnonce.first < INT_MAX){
          vector<string> data = prepareData(hashnonce.first,&pow);
          hashnonce.second = sha256(data);
          cout << hashnonce.second;
          hashInt = BigInt(hashnonce.second);

          if (hashInt<pow->target){
               break;
          }else{
               hashnonce.first++;
          }

     }
     cout << endl;

     return hashnonce;
}

class Blockchain  
{  
     public:     
     vector<Block> blockchain;  


     Block NewBlock(string data,string prevBlockHash){
         struct Block block;
         ProofOfWork pow = NewProofOfWork(&block);
         pair <int, string> hashnonce;
         hashnonce = Run(pow);

         block.Nonce = hashnonce.first;
         block.Hash = hashnonce.second;
         
         return block;
     }

    
     Blockchain(){
         blockchain = {NewBlock("Genesis Block", "")};
     }

     void AddBlock(string data ) {
         Block prevBlock = blockchain.back();
         Block newBlock = NewBlock(data, prevBlock.Hash);
         blockchain.push_back(newBlock);

     }
            
};

int main() {
	Blockchain bc = Blockchain();


	bc.AddBlock("Send 1 BTC to Ivan");
	bc.AddBlock("Send 2 more BTC to Ivan");

     vector<Block> blockchain = bc.blockchain;

	for (int i; i<blockchain.size();i++) {
		cout<<"Prev. hash: "<< blockchain.back().PrevBlockHash<<endl;
		cout<<"Data: "<< blockchain.back().Data<<endl;
		cout<<"Hash: "<< blockchain.back().Hash<<endl;
		
	}

     return 0;
}