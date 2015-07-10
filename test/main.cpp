#include <cstdio>
#include <ctime>
#include "..\cryptopp562\des.h"
#include "..\cryptopp562\aes.h"
#include "..\cryptopp562\randpool.h"
#include "..\cryptopp562\hex.h"
#include "..\cryptopp562\files.h"
#include "..\cryptopp562\\osrng.h"
#include "..\cryptopp562\rsa.h"

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
	byte inBlock[AES::BLOCKSIZE] = "123456789";    //要加密的数据块
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

	printf("key = %s, input = %s, output = %s, xor = %s, txt = %s\n", aesKey, inBlock, outBlock, xorBlock, plainText);
}

void RSA_Test()
{
	byte seed[1024] = "";
	AutoSeededRandomPool rnd;
	rnd.GenerateBlock(seed, sizeof(seed));
	printf("seed = %s\n", (char *)seed, strlen((char *)seed));

	RandomPool randPool;
	randPool.Put(seed, sizeof(seed));

	string message = "http://my.oschina.net/xlplbo/blog";
	printf("message = %s, length = %d\n", message.c_str(), strlen(message.c_str()));
	
	RSAES_OAEP_SHA_Decryptor pri(randPool, sizeof(seed));
	RSAES_OAEP_SHA_Encryptor pub(pri);
	printf("max plaintext Length = %d\n", pub.FixedMaxPlaintextLength());

	if (pub.FixedMaxPlaintextLength() > message.length())
	{
		string chilper;
		StringSource(message, true, new PK_EncryptorFilter(randPool, pub, new StringSink(chilper)));
		printf("chilper = %s, length = %d\n", chilper.c_str(), strlen(chilper.c_str()));
		
		string txt;
		StringSource(chilper, true, new PK_DecryptorFilter(randPool, pri, new StringSink(txt)));
		printf("txt = %s, length = %d\n", txt.c_str(), strlen(txt.c_str()));
	}
}

int main()
{
	DES_test();
	DES_EDE2_test();
	DES_EDE3_test();
	DES_XEX3_test();
	AES_test();
	RSA_Test();
}