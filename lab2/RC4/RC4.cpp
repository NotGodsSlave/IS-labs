#include "RC4.h"

void RC4::swap(int i, int j)
{
    uint8_t tmp = s[i];
    s[i] = s[j];
    s[j] = tmp;
}

void RC4::KeyScheduling(uint8_t* key, int keylen)
{
    for (int i = 0; i < 256; ++i)
    {
        s[i] = (uint8_t) i;
    }

    int j = 0;
    for (int i = 0; i < 256; ++i)
    {
        j = (j + s[i] + key[i%keylen]) % 256;
        swap(i,j);
    }
}

void RC4::Encrypt(uint8_t* in, uint8_t* out, int len)
{
    int i = 0; int j = 0;
    for (int k = 0; k < len; ++k)
    {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        swap(i,j);
        uint8_t t = (s[i]+s[j])%256;
        out[k] = in[k]^s[t];
    }
}