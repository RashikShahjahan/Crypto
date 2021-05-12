#include <iostream>
#include <vector>  
#include <string>
#include <utility> 
#include <cryptopp/integer.h> 
#include <cryptopp/sha.h> 
#include <sstream>
#include <chrono>
#include<ctime>



using namespace std;

//Specifies difficulty at which the block was mined
const int targetBits = 24;


// Struct defining a block
struct Block
     {  //Time block was created
        int Timestamp;
        // A cryptographic nonce
        int Nonce;
        // Data stored in the block
        string Data;
        // Result of hash function of previous block
	   string PrevBlockHash;
        // Result of hash function of current block
	   string Hash; 
     };


struct ProofOfWork
{
     Block *block;
     CryptoPP::Integer *target;
      
};

struct NonceHash{
     int nonce;
     string hash;
};

// Creates ProofOfWork Struct
ProofOfWork NewProofOfWork( Block *b) {
     // Target is 1 bit shifted by 256-targetbits
	CryptoPP::Integer target("1");
	target = target << (256-targetBits);
	ProofOfWork pow = ProofOfWork{b, &target};

	return pow;
}

// Convert decimal int to hex
string IntToHex(int decimal_value){
     stringstream ss;
     ss<< hex << decimal_value; 
     string res ( ss.str() );

     return res;
}

// Concatanates block members to create data to be hashed 
string prepareData(int nonce , ProofOfWork *pow){

     string data = pow->block->PrevBlockHash+pow->block->Data+IntToHex(pow->block->Timestamp)
     +IntToHex(targetBits)+IntToHex(nonce);

     return data;
}

// SHA256 algorithm
string SHA256(string data)
{
    byte const* pbData = (byte*) data.data();
    unsigned int nDataLen = data.size();
    // A pointer to the buffer to receive the hash
    byte abDigest[CryptoPP::SHA256::DIGESTSIZE];
    // Computes the hash
    CryptoPP::SHA256().CalculateDigest(abDigest, pbData, nDataLen);

    return string((char*)abDigest);
}

// Proof of work algorithm
NonceHash Run(ProofOfWork *pow){
     //CryptoPP::Integer hashInt = CryptoPP::Integer(const char *str);
     NonceHash hashnonce;
     hashnonce.nonce = 0;

     cout << "Mining the block containing" << pow->block->Data << endl;

     // Run while loop as long as nonce doesn't overflow
     while (hashnonce.nonce < INT_MAX){
          string data = prepareData(hashnonce.nonce,pow);
          hashnonce.hash = SHA256(data);
          cout << hashnonce.hash;
          // Convert hash to big integer hashInt
          CryptoPP::Integer hashInt(hashnonce.hash);

          // Beak out of the loop if hashInt is less than target 
          if (hashInt<*(pow->target)){
               break;
          // Otherwise increment nonce
          }else{
               hashnonce.nonce++;
          }

     }
     cout << endl;

     return hashnonce;
}

// Blockchain class
class Blockchain  
{  
     public:     
     vector<Block> blockchain;  

     // Create new block
     Block NewBlock(string data,string prevBlockHash){
         time_t result = time(nullptr);
         asctime(localtime(&result));
         struct Block block{result,0,data,prevBlockHash,""};
         ProofOfWork pow = NewProofOfWork(&block);
         NonceHash hashnonce;
         hashnonce = Run(&pow);

         block.Nonce = hashnonce.nonce;
         block.Hash = hashnonce.hash;
         
         return block;
     }

    // Constructor
     Blockchain(){
         blockchain = {NewBlock("Genesis Block", "")};
     }

     // Add block to blockchain
     void AddBlock(string data ) {
         Block prevBlock = blockchain.back();
         Block newBlock = NewBlock(data, prevBlock.Hash);
         blockchain.push_back(newBlock);

     }
            
};

// Test function 
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