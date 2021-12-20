#include<iostream>
#include "sha256/sha256.h"
#include "kupyna/kupyna.h"
#include<chrono>

int main()
{
    std::string str = "Whatever ";
    int i = 0;

    SHA256 sha;
    sha.update(str + std::to_string(i));
    uint8_t* digest1 = sha.digest();
    std::cout << SHA256::toString(digest1) << std::endl;

    Kupyna kupyna(256);
    uint8_t kupyna_hash1[64];
    const uint8_t* in_arr = reinterpret_cast<const uint8_t*>((str + std::to_string(i)).c_str());
    kupyna.hash(in_arr,512,kupyna_hash1);
    std::cout << Kupyna::toString(kupyna_hash1) << std::endl;

    i += 1;

    bool found = false;

    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();

    while (!found){
        SHA256 sha;
        sha.update(str + std::to_string(i));
        uint8_t* digest = sha.digest();
        found = true;
        for (int j = 0; j < 3; ++j)
        {
            if (digest[j] != digest1[j])
            {
                found = false;
                break;
            }
        }

        if (found)
        {
            std::cout << "Found partial collision on " << i << "-th attempt: " << SHA256::toString(digest) << std::endl;
        }
        else if (i % 10000000 == 0)
        {
            std::cout << i << "-th attempt: " << SHA256::toString(digest) << std::endl;
        }

        i += 1;
        delete[] digest;
    }

    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
    std::cout << "Time elapsed: " << std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count() << "[ms]" << std::endl;

    begin = std::chrono::steady_clock::now();
    i = 1;
    found = false;
    while (!found){
        Kupyna kupyna(256);
        uint8_t kupyna_hash[64];
        const uint8_t* in_arr = reinterpret_cast<const uint8_t*>((str + std::to_string(i)).c_str());
        kupyna.hash(in_arr,512,kupyna_hash);
        found = true;
        for (int j = 0; j < 2; ++j)
        {
            if (kupyna_hash[j] != kupyna_hash1[j])
            {
                found = false;
                break;
            }
        }

        if (found)
        {
            std::cout << "Found partial collision on " << i << "-th attempt: " << Kupyna::toString(kupyna_hash) << std::endl;
        }
        else if (i % 10000 == 0)
        {
            std::cout << i << "-th attempt: " << Kupyna::toString(kupyna_hash) << std::endl;
        }

        i += 1;
    }

    end = std::chrono::steady_clock::now();
    std::cout << "Time elapsed: " << std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count() << "[ms]" << std::endl;
}