#include <cassert>
#include <climits>
#include <cstdint>
#include <cstring>
#include <string>

using namespace std;

class Salsa20
{
public:
                
    enum: size_t
    {
        VECTOR_SIZE = 16,
        BLOCK_SIZE = 64,
        KEY_SIZE = 32,
        IV_SIZE = 8,
        ROUNDS = 20,
        NUM_OF_BLOCKS_PER_CHUNK = 8192
    };
    void setKey(const uint8_t* key);
    void setIv(const uint8_t* iv);
    void generateKeyStream(uint8_t output[BLOCK_SIZE]);
    void processBlocks(const uint8_t* input, uint8_t* output, size_t numBlocks);
    void processBytes(const uint8_t* input, uint8_t* output, size_t numBytes);
    uint8_t* processString(string input, uint64_t& outLen);
    string toString(uint8_t* data);

private:
    uint32_t rotate(uint32_t value, uint32_t numBits);
    void qr(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d);
    void convert(uint32_t value, uint8_t* array);
    uint32_t convert(const uint8_t* array);

    uint32_t vector_[VECTOR_SIZE];
};