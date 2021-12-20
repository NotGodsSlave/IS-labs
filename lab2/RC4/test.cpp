#include<iostream>
#include "RC4.h"
#include <string>
#include "string.h"
#include<cstdint>

using namespace std;


int main()
{
    string pltxtstr = "In 27 BC senate granted Octavian the title and the name of Augustus, \"The Exhalted One\". That title will eventually become traditional Roman Emperor title.";
    int len = pltxtstr.length();
    const char* plaintext = pltxtstr.c_str();
    string keystr = "This is a key";
    int keylen = keystr.length();
    const char* key = keystr.c_str();

    uint8_t* ciphertext = new uint8_t[pltxtstr.size() + 1];
    uint8_t* decrypted = new uint8_t[pltxtstr.size() + 1];

    RC4 rc4;
    rc4.KeyScheduling((uint8_t*) key, keylen);
    rc4.Encrypt((uint8_t*) plaintext, ciphertext, len);
    rc4.KeyScheduling((uint8_t*) key, keylen);
    rc4.Encrypt(ciphertext, decrypted, len);

    cout << "Encrypted message:\n";
    for (int i = 0; i < len; ++i)
    {
        cout << std::hex << (int) ciphertext[i] << " ";
    }
    cout << endl;
    cout << "Decrypted message:\n";
    cout << decrypted << endl;
    delete[] ciphertext;
    delete[] decrypted;
}