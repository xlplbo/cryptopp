#include <cstdio>
#include <ctime>
#include <iostream>
#include "..\cryptopp562\des.h"

#include "..\cryptopp562\aes.h"
#include "..\cryptopp562\modes.h"

#include "..\cryptopp562\randpool.h"
#include "..\cryptopp562\\osrng.h"
#include "..\cryptopp562\rsa.h"

#include "..\cryptopp562\hex.h"

using namespace std;
using namespace CryptoPP;

void DES_test()
{
	byte key[DES::KEYLENGTH] = "1234567";
	byte input[DES::BLOCKSIZE] = "123457";
	byte output[DES::BLOCKSIZE] = "";
	byte txt[DES::BLOCKSIZE] = "";

	DESEncryption desEn;
	desEn.SetKey(key, DES::KEYLENGTH);
	desEn.ProcessBlock(input, output);
	DESDecryption desDe;
	desDe.SetKey(key, DES::KEYLENGTH);
	desDe.ProcessBlock(output, txt);

	printf("key = %s, input = %s, output = %s, txt = %s\n", key, input, output, txt);
}

void DES_EDE2_test()
{
	byte key[DES_EDE2::KEYLENGTH] = "1234567890abcde";
	byte input[DES_EDE2::BLOCKSIZE] = "123457";
	byte output[DES_EDE2::BLOCKSIZE] = "";
	byte txt[DES_EDE2::BLOCKSIZE] = "";

	DES_EDE2_Encryption desEn;
	desEn.SetKey(key, DES_EDE2::KEYLENGTH);
	desEn.ProcessBlock(input, output);
	DES_EDE2_Decryption desDe;
	desDe.SetKey(key, DES_EDE2::KEYLENGTH);
	desDe.ProcessBlock(output, txt);

	printf("key = %s, input = %s, output = %s, txt = %s\n", key, input, output, txt);
}

void DES_EDE3_test()
{
	byte key[DES_EDE3::KEYLENGTH] = "1234567890abcdefghijlmn";
	byte input[DES_EDE3::BLOCKSIZE] = "123457";
	byte output[DES_EDE3::BLOCKSIZE] = "";
	byte txt[DES_EDE3::BLOCKSIZE] = "";

	DES_EDE3_Encryption desEn;
	desEn.SetKey(key, DES_EDE3::KEYLENGTH);
	desEn.ProcessBlock(input, output);
	DES_EDE3_Decryption desDe;
	desDe.SetKey(key, DES_EDE3::KEYLENGTH);
	desDe.ProcessBlock(output, txt);

	printf("key = %s, input = %s, output = %s, txt = %s\n", key, input, output, txt);
}

void DES_XEX3_test()
{
	byte key[DES_XEX3::KEYLENGTH] = "1234567890abcdefghijlmn";
	byte input[DES_XEX3::BLOCKSIZE] = "123457";
	byte output[DES_XEX3::BLOCKSIZE] = "";
	byte txt[DES_XEX3::BLOCKSIZE] = "";

	DES_XEX3_Encryption desEn;
	desEn.SetKey(key, DES_EDE3::KEYLENGTH);
	desEn.ProcessBlock(input, output);
	DES_XEX3_Decryption desDe;
	desDe.SetKey(key, DES_EDE3::KEYLENGTH);
	desDe.ProcessBlock(output, txt);

	printf("key = %s, input = %s, output = %s, txt = %s\n", key, input, output, txt);
}

void AES_test()
{
	byte aesKey[AES::DEFAULT_KEYLENGTH] = "abcdefg";  //密钥
	byte inBlock[AES::BLOCKSIZE] = "1234567";    //要加密的数据块
	byte outBlock[AES::BLOCKSIZE]; //加密后的密文块
	byte xorBlock[AES::BLOCKSIZE]; //必须设定为全零
	byte plainText[AES::BLOCKSIZE]; //解密

	memset(xorBlock, 0, AES::BLOCKSIZE ); //置零

	AESEncryption aesEncryptor; //加密器 
	aesEncryptor.SetKey( aesKey, AES::DEFAULT_KEYLENGTH );  //设定加密密钥
	aesEncryptor.ProcessAndXorBlock( inBlock, xorBlock, outBlock );  //加密

	AESDecryption aesDecryptor;
	aesDecryptor.SetKey( aesKey, AES::DEFAULT_KEYLENGTH );
	aesDecryptor.ProcessAndXorBlock( outBlock, xorBlock, plainText );

	printf("output = %s size = %d\n", outBlock, strlen((char *)outBlock));

	AutoSeededRandomPool prng;

	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	prng.GenerateBlock( key, key.size() );

	byte iv[ AES::BLOCKSIZE ];
	prng.GenerateBlock( iv, sizeof(iv) );

	string plain = "CBC Mode Test";
	string cipher, encoded, recovered;

	/*********************************\
	\*********************************/

	try
	{
		cout << "plain text: " << plain << endl;

		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV( key, key.size(), iv );

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource ss( plain, true, 
			new StreamTransformationFilter( e,
			new StringSink( cipher )
			) // StreamTransformationFilter      
			); // StringSource
	}
	catch( const CryptoPP::Exception& e )
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print cipher text
	StringSource ss( cipher, true,
		new HexEncoder(
		new StringSink( encoded )
		) // HexEncoder
		); // StringSource
	cout << "cipher text: " << encoded << endl;

	/*********************************\
	\*********************************/

	try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV( key, key.size(), iv );

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource ss( cipher, true, 
			new StreamTransformationFilter( d,
			new StringSink( recovered )
			) // StreamTransformationFilter
			); // StringSource

		cout << "recovered text: " << recovered << endl;
	}
	catch( const CryptoPP::Exception& e )
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

void RSA_Test()
{
	//待加密的字符串
	string message = "http://my.oschina.net/xlplbo/blog";
	printf("message = %s, length = %d\n", message.c_str(), strlen(message.c_str()));

	/*
	//自动生成随机数据
	byte seed[600] = "";
	AutoSeededRandomPool rnd;
	rnd.GenerateBlock(seed, sizeof(seed));
	printf("seed = %s\n", (char *)seed, strlen((char *)seed));

	//生成加密的高质量伪随机字节播种池一体化后的熵
	RandomPool randPool;
	randPool.Put(seed, sizeof(seed));
	*/

	AutoSeededRandomPool rnd;
	InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rnd, 1024);

	RSA::PrivateKey privateKey(params);
	RSA::PublicKey publicKey(params);
	
	//使用OAEP模式
	//RSAES_OAEP_SHA_Decryptor pri(randPool, sizeof(seed));
	//RSAES_OAEP_SHA_Encryptor pub(pri);
	RSAES_OAEP_SHA_Decryptor pri(privateKey);
	RSAES_OAEP_SHA_Encryptor pub(publicKey);
	printf("max plaintext Length = %d,%d\n", pri.FixedMaxPlaintextLength(), pub.FixedMaxPlaintextLength());
	if (pub.FixedMaxPlaintextLength() > message.length())
	{//待加密文本不能大于最大加密长度
		string chilper;
		StringSource(message, true, new PK_EncryptorFilter(rnd, pub, new StringSink(chilper)));
		printf("chilper = %s, length = %d\n", chilper.c_str(), strlen(chilper.c_str()));
		
		string txt;
		StringSource(chilper, true, new PK_DecryptorFilter(rnd, pri, new StringSink(txt)));
		printf("txt = %s, length = %d\n", txt.c_str(), strlen(txt.c_str()));
	}

	//使用PKCS1v15模式
	//RSAES_PKCS1v15_Decryptor pri1(randPool, sizeof(seed));
	//RSAES_PKCS1v15_Encryptor pub1(pri1);
	RSAES_PKCS1v15_Decryptor pri1(privateKey);
	RSAES_PKCS1v15_Encryptor pub1(publicKey);
	printf("max plaintext Length = %d,%d\n", pri1.FixedMaxPlaintextLength(), pub1.FixedMaxPlaintextLength());
	if (pub1.FixedMaxPlaintextLength() > message.length())
	{//待加密文本不能大于最大加密长度
		string chilper;
		StringSource(message, true, new PK_EncryptorFilter(rnd, pub1, new StringSink(chilper)));
		printf("chilper = %s, length = %d\n", chilper.c_str(), strlen(chilper.c_str()));

		string txt;
		StringSource(chilper, true, new PK_DecryptorFilter(rnd, pri1, new StringSink(txt)));
		printf("txt = %s, length = %d\n", txt.c_str(), strlen(txt.c_str()));
	}
}

void test()
{
	////////////////////////////////////////////////
	// Generate keys
	AutoSeededRandomPool rng;

	InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize( rng, 1536 );

	RSA::PrivateKey privateKey( params );
	RSA::PublicKey publicKey( params );

	string plain="RSA Encryption", cipher, recovered;

	////////////////////////////////////////////////
	// Encryption
	RSAES_OAEP_SHA_Encryptor e( publicKey );

	StringSource ss1( plain, true,
		new PK_EncryptorFilter( rng, e,
			new StringSink( cipher )
		) // PK_EncryptorFilter
	 ); // StringSource

	////////////////////////////////////////////////
	// Decryption
	RSAES_OAEP_SHA_Decryptor d( privateKey );

	StringSource ss2( cipher, true,
		new PK_DecryptorFilter( rng, d,
			new StringSink( recovered )
		) // PK_DecryptorFilter
	 ); // StringSource

	assert( plain == recovered );
}
int main()
{
	//DES_test();
	//DES_EDE2_test();
	//DES_EDE3_test();
	//DES_XEX3_test();
	AES_test();
	//RSA_Test();
	test();
}