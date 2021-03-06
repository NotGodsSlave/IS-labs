#include "AES.h"
#include<iostream>

using namespace std;

int main()
{
    AES aes(128);
    uint8_t plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t right[] = { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };
    unsigned int len = 0;

    // testing for character input
    uint8_t *out = aes.Encrypt(plain, 16, key, len);
    cout << len << '\n';
    for (int i = 0; i < len; ++i)
    {
        cout << std::hex << (int)out[i];
    }
    cout << '\n';
    uint8_t *dec = aes.Decrypt(out,16,key);
    for (int i = 0; i < len; ++i)
    {
        cout << std::hex << (int)out[i];
    }
    cout << '\n';

    // testing for string input
    string string_to_enc = "One day I will come up with better test string";
    out = aes.Encrypt(string_to_enc, key, len);
    cout << len << '\n';

    cout << "Encrypted data:\n";
    string encr = aes.ToString(out);
    for (int i = 0; i < len; ++i)
    {
        cout << std::hex << (int)out[i];
    }
    cout << '\n';
    cout << encr << '\n';

    cout << "Decrypted data:\n";
    dec = aes.Decrypt(encr,key);
    for (int i = 0; i < len; ++i)
    {
        cout << std::hex << (int)dec[i];
    }
    cout << '\n';
    string decr = aes.ToString(dec);
    cout << decr << '\n';

    delete[] out;
    delete[] dec;
}