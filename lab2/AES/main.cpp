#include "AES.h"
#include<iostream>

using namespace std;

int main()
{
    AES aes(128);
    uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t iv[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    unsigned int len = 0;

    string string_to_enc = "The Mongol Empire was the largest land-connected country in human history, and it was built in mere 50 years!";
    string N = "The Weirdo Empire was the largest land connected country in human history, and it was built in mere 50 years!";

    // ECB
    cout << "Encryption using ECB\n";
    uint8_t* out = aes.EncryptECB(string_to_enc, key, len);
    //cout << len << '\n';

    cout << "Encrypted data:\n";
    string encr = aes.ToString(out);
    for (int i = 0; i < len; ++i)
    {
        cout << std::hex << (int)out[i];
    }
    cout << '\n';

    cout << "Decrypted data:\n";
    uint8_t* dec = aes.DecryptECB(encr,key);
    string decr = aes.ToString(dec);
    cout << decr << '\n';
    
    //-----------------------------------------------------------
    cout << "-------------------------------------------------\n";

    // CBC
    cout << "Encryption using CBC\n";
    out = aes.EncryptCBC(string_to_enc, key, iv, len);
    //cout << len << '\n';

    cout << "Encrypted data:\n";
    encr = aes.ToString(out);
    for (int i = 0; i < len; ++i)
    {
        cout << std::hex << (int)out[i];
    }
    cout << '\n';

    cout << "Decrypted data:\n";
    dec = aes.DecryptCBC(encr, key, iv);
    decr = aes.ToString(dec);
    cout << decr << '\n';

    //--------------------------------------------------------
    cout << "-------------------------------------------------\n";

    // CFB
    cout << "Encryption using CFB\n";
    out = aes.EncryptCFB(string_to_enc, key, iv, len);
    //cout << len << '\n';

    cout << "Encrypted data:\n";
    encr = aes.ToString(out);
    for (int i = 0; i < len; ++i)
    {
        cout << std::hex << (int)out[i];
    }
    cout << '\n';

    cout << "Decrypted data:\n";
    dec = aes.DecryptCFB(encr, key, iv);
    decr = aes.ToString(dec);
    cout << decr << '\n';

    //---------------------------------------------------------
    cout << "-------------------------------------------------\n";

    //CTR
    cout << "Encryption using CTR\n";
    out = aes.EncryptCTR(string_to_enc, N, key);

    cout << "Encrypted data:\n";
    for (int i = 0; i < N.size(); ++i)
    {
        cout << std::hex << (int)out[i];
    }
    cout << '\n';

    cout << "Decrypted data:\n";
    dec = aes.DecryptCTR(out, N, key);
    decr = aes.ToString(dec);
    cout << decr << '\n';

    delete[] out;
    delete[] dec;
}