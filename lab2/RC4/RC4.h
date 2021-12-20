#include<iostream>
#include<cstdint>

class RC4
{
public:
    void Encrypt(uint8_t* plaintext, uint8_t* ciphertext, int len);
    void KeyScheduling(uint8_t* key, int keylen);
private:
    void swap(int i, int j);
    uint8_t s[256];
};
