#include "salsa20.h"
#include<iostream>

using namespace std;

#define NUM_OF_BLOCKS_PER_CHUNK 8192

int main()
{
    uint8_t key[32] = {0x06, 0x9e, 0xeb, 0x2e, 0x94, 0xc0, 0xfc, 0xcf, 0x15, 0x27, 0x6d, 0xbf, 0x65, 0x58, 0xb1, 0xd6,
                        0x2b, 0xd8, 0x86, 0x50, 0xf8, 0xbc, 0x65, 0xbf, 0x5c, 0x51, 0x43, 0x4e, 0x97, 0x51, 0xe7, 0xfe};
    uint8_t iv[8] = {0xfc, 0x6e, 0xec, 0x1e, 0xeb, 0x44, 0xbc, 0xf0};
    Salsa20 salsa20;
    salsa20.setKey(key);
    salsa20.setIv(iv);

    string test_str = "After the failed siege of Vienna in 1683 Ottomans would never again push this far into Europe.";
    uint64_t len = 0;
    uint8_t* res = salsa20.processString(test_str, len);

    for (int i = 0; i < len; ++i)
    {
        cout << hex << (int)res[i] << " ";
    }
    cout << endl;

    salsa20.setKey(key);
    salsa20.setIv(iv);
    uint8_t* deciphred = new uint8_t[len];
    salsa20.processBytes(res,deciphred,len);
    string dcphr = salsa20.toString(deciphred);
    cout << dcphr << endl;
}