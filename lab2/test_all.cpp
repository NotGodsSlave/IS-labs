#include<iostream>
#include<fstream>
#include<string>
#include<chrono>
#include<sstream>
#include "AES/AES.h"
#include "RC4/RC4.h"
#include "Salsa20/salsa20.h"

using namespace std;

int main()
{
    ifstream fin;
    fin.open("data/TestInput10mb.txt");

    string text;
    stringstream buffer;
    buffer << fin.rdbuf();
    text = buffer.str();
    const char* plaintext = text.c_str();
    int lentxt = text.size();

    //RC4 test
    cout << "Testing RC4...\n";

    string keystr = "This is a key";
    int keylen = keystr.length();
    const char* keyrc4 = keystr.c_str();

    uint8_t* ciphertext = new uint8_t[text.size() + 1];

    chrono::steady_clock::time_point begin = chrono::steady_clock::now();
    cout << "Starting encryption\n";

    RC4 rc4;
    rc4.KeyScheduling((uint8_t*) keyrc4, keylen);
    rc4.Encrypt((uint8_t*) plaintext, ciphertext, lentxt);

    cout << "Text Encrypted.\n";
    chrono::steady_clock::time_point end = chrono::steady_clock::now();
    cout << "Time elapsed: " << chrono::duration_cast<chrono::milliseconds>(end - begin).count() 
                << "[ms]" << endl;
    cout << "-------------------------------------------------------------\n";

    //Salsa20 test
    cout << "Testing Salsa20...\n";

    uint8_t keysls[32] = {0x06, 0x9e, 0xeb, 0x2e, 0x94, 0xc0, 0xfc, 0xcf, 0x15, 0x27, 0x6d, 0xbf, 0x65, 0x58, 0xb1, 0xd6,
                        0x2b, 0xd8, 0x86, 0x50, 0xf8, 0xbc, 0x65, 0xbf, 0x5c, 0x51, 0x43, 0x4e, 0x97, 0x51, 0xe7, 0xfe};
    uint8_t ivsls[8] = {0xfc, 0x6e, 0xec, 0x1e, 0xeb, 0x44, 0xbc, 0xf0};
    Salsa20 salsa20;
    salsa20.setKey(keysls);
    salsa20.setIv(ivsls);

    begin = chrono::steady_clock::now();
    cout << "Starting encryption\n";

    uint64_t lensls = 0;
    uint8_t* res = salsa20.processString(text, lensls);

    cout << "Text Encrypted.\n";
    end = chrono::steady_clock::now();
    cout << "Time elapsed: " << chrono::duration_cast<chrono::milliseconds>(end - begin).count() 
                << "[ms]" << endl;

    delete[] res;
    cout << "-------------------------------------------------------------\n";

    //AES tests
    cout << "Testing AES stuf...\n";

    AES aes(128);
    uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t iv[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    string N = text;
    unsigned int len = 0;

    // ECB
    cout << "Encryption using ECB\n";
    
    begin = chrono::steady_clock::now();
    cout << "Starting encryption\n";
    uint8_t* out = aes.EncryptECB(text, key, len);
    cout << "Text Encrypted.\n";
    end = chrono::steady_clock::now();
    cout << "Time elapsed: " << chrono::duration_cast<chrono::milliseconds>(end - begin).count() 
                << "[ms]" << endl;
    
    //-----------------------------------------------------------
    cout << "-------------------------------------------------\n";

    // CBC
    cout << "Encryption using CBC\n";

    begin = chrono::steady_clock::now();
    cout << "Starting encryption\n";
    out = aes.EncryptCBC(text, key, iv, len);
    cout << "Text Encrypted.\n";
    end = chrono::steady_clock::now();
    cout << "Time elapsed: " << chrono::duration_cast<chrono::milliseconds>(end - begin).count() 
                << "[ms]" << endl;

    //--------------------------------------------------------
    cout << "-------------------------------------------------\n";

    // CFB
    cout << "Encryption using CFB\n";

    begin = chrono::steady_clock::now();
    cout << "Starting encryption\n";
    out = aes.EncryptCFB(text, key, iv, len);
    cout << "Text Encrypted.\n";
    end = chrono::steady_clock::now();
    cout << "Time elapsed: " << chrono::duration_cast<chrono::milliseconds>(end - begin).count() 
                << "[ms]" << endl;

    //---------------------------------------------------------
    cout << "-------------------------------------------------\n";

    //CTR
    cout << "Encryption using CTR\n";

    begin = chrono::steady_clock::now();
    cout << "Starting encryption\n";
    out = aes.EncryptCTR(text, N, key);
    cout << "Text Encrypted.\n";
    end = chrono::steady_clock::now();
    cout << "Time elapsed: " << chrono::duration_cast<chrono::milliseconds>(end - begin).count() 
                << "[ms]" << endl;

    delete[] out;
}