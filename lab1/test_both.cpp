#include<iostream>
#include<fstream>
#include<chrono>
#include "AES/AES.h"
#include "Kalyna/kalyna.h"

using namespace std;

int main()
{
    ifstream fin;
    fin.open("data/TestInput10mb.txt");

    string text;
    std::stringstream buffer;
    buffer << fin.rdbuf();
    text = buffer.str();

    // testing AES
    cout << "Testing AES...\n";
    ofstream fout;
    fout.open("data/outputAES1.txt");

    AES aes(128);
    unsigned int outlen;
    uint8_t key128[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    chrono::steady_clock::time_point begin = chrono::steady_clock::now();
    cout << "Starting Encryption...\n";

    uint8_t* out = aes.Encrypt(text, key128, outlen);

    cout << "Text Encrypted.\n";
    chrono::steady_clock::time_point end = chrono::steady_clock::now();
    cout << "Time elapsed: " << chrono::duration_cast<chrono::milliseconds>(end - begin).count() 
                << "[ms]" << endl;

    for (int i = 0; i < outlen; ++i)
    {
        fout << hex << (int)out[i];
    }
    delete[] out;

    //testing Kalyna
    cout << "Testing Kalyna...\n";
    fout.open("data/outputKalyna1.txt");

    Kalyna kalyna(128,128);
    int outLen = 0;
    uint64_t kalynakey22[2] = {0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL};

    begin = chrono::steady_clock::now();
    cout << "Starting Encryption...\n";

    uint64_t* kalyna_out = kalyna.EncryptString(text, kalynakey22, outLen);

    cout << "Text Encrypted.\n";
    end = chrono::steady_clock::now();
    cout << "Time elapsed: " << chrono::duration_cast<chrono::milliseconds>(end - begin).count() 
                << "[ms]" << endl;

    for (int i = 0; i < outLen; ++i)
    {
        fout << hex << (int)kalyna_out[i];
    }
}