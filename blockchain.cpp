#include <iostream>
#include <vector>  
#include <string>
#include <utility> 
#include <cryptopp/integer.h> 
#include <cryptopp/sha.h> 
#include <sstream>
#include <chrono>
#include<ctime>
#include <nlohmann/json.hpp>
#include <leveldb/db.h>
#include <cassert>


using nlohmann::json;
using namespace std;
namespace ns{
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
     char* hash;
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
char* SHA256(string data)
{
    byte const* pbData = (byte*) data.data();
    unsigned int nDataLen = data.size();
    // A pointer to the buffer to receive the hash
    byte abDigest[CryptoPP::SHA256::DIGESTSIZE];
    // Computes the hash
    CryptoPP::SHA256().CalculateDigest(abDigest, pbData, nDataLen);

    return (char*)abDigest;
}

// Proof of work algorithm
NonceHash Run(ProofOfWork *pow){
     NonceHash hashnonce;
     hashnonce.nonce = 0;

     cout << "Mining the block containing " << pow->block->Data << endl;

     // Run while loop as long as nonce doesn't overflow
     while (hashnonce.nonce < INT_MAX){
          string data = prepareData(hashnonce.nonce,pow);
          byte const* pbData = (byte*) data.data();
          unsigned int nDataLen = data.size();
          // A pointer to the buffer to receive the hash
          byte abDigest[CryptoPP::SHA256::DIGESTSIZE];

          // Computes the hash
          CryptoPP::SHA256().CalculateDigest(abDigest, pbData, nDataLen);
          hashnonce.hash = (char*)abDigest;

          
          cout << hashnonce.hash;
          // Convert hash to big integer hashInt
          CryptoPP::Integer hashInt((hashnonce.hash));

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

bool Validate(ProofOfWork* pow) {

	string data = prepareData(pow->block->Nonce,pow);
	byte const* pbData = (byte*) data.data();
     unsigned int nDataLen = data.size();
          
     byte abDigest[CryptoPP::SHA256::DIGESTSIZE];

     CryptoPP::SHA256().CalculateDigest(abDigest, pbData, nDataLen);
     char* hash = (char*)abDigest;

	CryptoPP::Integer hashInt(hash);

	if (hashInt<*(pow->target)){
               return true;
          
     }else{
               return false;
          }
}


     void Serialize(json& j, const Block& b) {
        j = json{ {"Timestamp", b.Timestamp}, {"Nonce", b.Nonce}, {"Data", b.Data},{"PrevBlockHash",b.PrevBlockHash},{"Hash",b.Hash} };
    }
            
     void Deserialize(const json& j, Block& b) {
        j.at("Timestamp").get_to(b.Timestamp);
        j.at("Nonce").get_to(b.Nonce);
        j.at("Data").get_to(b.Data);
        j.at("PrevBlockHash").get_to(b.PrevBlockHash);
        j.at("Hash").get_to(b.Hash);
    }


// Blockchain class
class Blockchain  
{  
     public:     
     vector<Block> blockchain;  
     string tip; 
     leveldb::DB* db;
     
     // Create new block
     Block NewBlock(string data,string prevBlockHash){
         time_t result = time(nullptr);
         asctime(localtime(&result));
         struct Block block{int(result),0,data,prevBlockHash,""};
         ProofOfWork pow = NewProofOfWork(&block);
         NonceHash hashnonce;
         hashnonce = Run(&pow);

         block.Nonce = hashnonce.nonce;
         block.Hash = hashnonce.hash;
         
         return block;
     }


    // Constructor
     Blockchain(){
         leveldb::Options options;
         options.create_if_missing = true;

         leveldb::Status status = leveldb::DB::Open(options, "/tmp/testdb", &db);
         assert(status.ok());

         leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());
         it->SeekToFirst(); 
         if(it->Valid() == false){
             Block genesis =  NewBlock("Genesis block","");
             json j;
             Serialize(j,genesis);
             status = db->Put(leveldb::WriteOptions(), genesis.Hash, j);
             status = db->Put(leveldb::WriteOptions(), "l", genesis.Hash);
             tip = genesis.Hash;

         }

         else{
              status = db->Get(leveldb::ReadOptions(), "l", &tip);
         }


     }

     // Add block to blockchain
     void AddBlock(string data ) {
         Block prevBlock = blockchain.back();
         Block newBlock = NewBlock(data, prevBlock.Hash);
         blockchain.push_back(newBlock);

     }

};

}


// Test function 
int main() {
     using namespace ns;
	Blockchain bc = Blockchain();


	bc.AddBlock("Send 1 BTC to Ivan");
	bc.AddBlock("Send 2 more BTC to Ivan");

     vector<Block> blockchain = bc.blockchain;

	for (unsigned int i = 0; i<blockchain.size();i++) {
		cout<<"Prev. hash: "<< blockchain.back().PrevBlockHash<<endl;
		cout<<"Data: "<< blockchain.back().Data<<endl;
		cout<<"Hash: "<< blockchain.back().Hash<<endl;
		ProofOfWork pow = NewProofOfWork(&blockchain.back());
		cout<<boolalpha<<"PoW: "<< Validate(&pow)<<endl;
		
	}

     return 0;
}