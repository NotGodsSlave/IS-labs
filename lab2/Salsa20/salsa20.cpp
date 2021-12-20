#include "salsa20.h"
#include<string>
#include<iostream>

void Salsa20::setKey(const uint8_t* key)
{
    static const char constants[] = "expand 32-byte k";

    if(key == nullptr)
        return;

    vector_[0] = convert(reinterpret_cast<const uint8_t*>(&constants[0]));
    vector_[1] = convert(&key[0]);
    vector_[2] = convert(&key[4]);
    vector_[3] = convert(&key[8]);
    vector_[4] = convert(&key[12]);
    vector_[5] = convert(reinterpret_cast<const uint8_t*>(&constants[4]));

    std::memset(&vector_[6], 0, 4 * sizeof(uint32_t));

    vector_[10] = convert(reinterpret_cast<const uint8_t*>(&constants[8]));
    vector_[11] = convert(&key[16]);
    vector_[12] = convert(&key[20]);
    vector_[13] = convert(&key[24]);
    vector_[14] = convert(&key[28]);
    vector_[15] = convert(reinterpret_cast<const uint8_t*>(&constants[12]));
}

void Salsa20::setIv(const uint8_t* iv)
{
    if(iv == nullptr)
        return;

    vector_[6] = convert(&iv[0]);
    vector_[7] = convert(&iv[4]);
    vector_[8] = vector_[9] = 0;
}

void Salsa20::generateKeyStream(uint8_t output[BLOCK_SIZE])
{
    uint32_t x[VECTOR_SIZE];
    std::memcpy(x, vector_, sizeof(vector_));

    for(int i = 0; i < ROUNDS; i+=2)
    {
        // even rounds
        qr(x[0],x[4],x[8],x[12]);
        qr(x[5],x[9],x[13],x[1]);
        qr(x[10],x[14],x[2],x[6]);
        qr(x[15],x[3],x[7],x[11]);
        // odd rounds
        qr(x[0],x[1],x[2],x[3]);
        qr(x[5],x[6],x[7],x[4]);
        qr(x[10],x[11],x[8],x[9]);
        qr(x[15],x[12],x[13],x[14]);
    }

    for(size_t i = 0; i < VECTOR_SIZE; ++i)
    {
        x[i] += vector_[i];
        convert(x[i], &output[4 * i]);
    }

    ++vector_[8];
    vector_[9] += vector_[8] == 0 ? 1 : 0;
}

void Salsa20::processBlocks(const uint8_t* input, uint8_t* output, size_t numBlocks)
{
    assert(input != nullptr && output != nullptr);

    uint8_t keyStream[BLOCK_SIZE];

    for(size_t i = 0; i < numBlocks; ++i)
    {
        generateKeyStream(keyStream);
        for(size_t j = 0; j < BLOCK_SIZE; ++j)
        {
            *(output++) = keyStream[j] ^ *(input++);
        }
    }
}

void Salsa20::processBytes(const uint8_t* input, uint8_t* output, size_t numBytes)
{
    assert(input != nullptr && output != nullptr);

    uint8_t keyStream[BLOCK_SIZE];
    size_t numBytesToProcess;

    while(numBytes != 0)
    {
        generateKeyStream(keyStream);
        numBytesToProcess = numBytes >= BLOCK_SIZE ? BLOCK_SIZE : numBytes;

        for(size_t i = 0; i < numBytesToProcess; ++i, --numBytes)
            *(output++) = keyStream[i] ^ *(input++);
    }
}

uint32_t Salsa20::rotate(uint32_t value, uint32_t numBits)
{
    return (value << numBits) | (value >> (32 - numBits));
}

void Salsa20::qr(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d)
{
    b ^= rotate((a + d), 7);
    c ^= rotate((b + a), 9);
    d ^= rotate((c + b), 13);
    a ^= rotate((d + c), 18);
}

void Salsa20::convert(uint32_t value, uint8_t* array)
{
    array[0] = static_cast<uint8_t>(value >> 0);
    array[1] = static_cast<uint8_t>(value >> 8);
    array[2] = static_cast<uint8_t>(value >> 16);
    array[3] = static_cast<uint8_t>(value >> 24);
}

uint32_t Salsa20::convert(const uint8_t* array)
{
    return ((static_cast<uint32_t>(array[0]) << 0)  |
        (static_cast<uint32_t>(array[1]) << 8)  |
        (static_cast<uint32_t>(array[2]) << 16) |
        (static_cast<uint32_t>(array[3]) << 24));
}

uint8_t* Salsa20::processString(std::string input, uint64_t& outLen)
{
    outLen = input.size();
    const uint64_t chunkSize = NUM_OF_BLOCKS_PER_CHUNK * BLOCK_SIZE;
    uint64_t numChunks = input.size() / chunkSize;
    uint64_t remainderSize = input.size() % chunkSize;
    uint8_t* out = new uint8_t[outLen];

    uint64_t i = 0;
    for (; i < numChunks; ++i)
    {
        std::string sbstr = input.substr(i*chunkSize,chunkSize);
        const uint8_t* in = reinterpret_cast<const uint8_t*>(sbstr.c_str());
        processBlocks(in,out+i*numChunks,NUM_OF_BLOCKS_PER_CHUNK);
    }
    if (remainderSize > 0)
    {
        std::string sbstr = input.substr(i*chunkSize,remainderSize);
        const uint8_t* in = reinterpret_cast<const uint8_t*>(sbstr.c_str());
        processBytes(in,out+i*numChunks,remainderSize);
    }

    return out;
}

string Salsa20::toString(uint8_t* data)
{
    string converted(reinterpret_cast<char*>(data));
    return converted;
}