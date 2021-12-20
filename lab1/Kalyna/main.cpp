#include <stdio.h>
#include <memory.h>
#include <iostream>

#include "kalyna.h"

using namespace std;

void print (int data_size, uint64_t data []);

int main(int argc, char** argv) {

    //trying ciphering texts with Kalyna
    Kalyna kalyna_test(128,128);
    string test_string = "I hate Kalyna. No, honestly, I wholeheartedly do! Something Ig";
    uint64_t key_test[2] = {0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL};

    int len = 0;
    uint64_t* should_be_ciphered = kalyna_test.EncryptString(test_string, key_test, len);
    uint64_t* should_be_deciphered = kalyna_test.DecryptString(should_be_ciphered,key_test,len);
    uint8_t* deciphered_bytes = kalyna_test.WordsToBytes(len, should_be_deciphered);
    string fin = kalyna_test.BytesToString(deciphered_bytes);
    cout << fin << endl;

    return 0;
}
