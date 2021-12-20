#include "kalyna.h"
#include<iostream>

Kalyna::Kalyna(size_t block_size, size_t key_size) {
    int i;

    if (block_size == kBLOCK_128) {
        this->nb = kBLOCK_128 / kBITS_IN_WORD;
        if (key_size == kKEY_128) {
            this->nk = kKEY_128 / kBITS_IN_WORD;
            this->nr = kNR_128;
        } else if (key_size == kKEY_256){
            this->nk =  kKEY_256 / kBITS_IN_WORD;
            this->nr = kNR_256;
        } else {
            std::cout << "Error: unsupported key size.\n";
        }
    } else if (block_size == kBLOCK_256) {
        this->nb = kBLOCK_256 / kBITS_IN_WORD;
        if (key_size == kKEY_256) {
            this->nk = kKEY_256 / kBITS_IN_WORD;
            this->nr = kNR_256;
        } else if (key_size == kKEY_512){
            this->nk = kKEY_512 / kBITS_IN_WORD;
            this->nr = kNR_512;
        } else {
            std::cout << "Error: unsupported key size.\n";
        }
    } else if (block_size == kBLOCK_512) {
        this->nb = kBLOCK_512 / kBITS_IN_WORD;
        if (key_size == kKEY_512) {
            this->nk = kKEY_512 / kBITS_IN_WORD;
            this->nr = kNR_512;
        } else {
            std::cout << "Error: unsupported key size.\n";
        }
    } else {
        std::cout << "Error: unsupported block size.\n";
    }

    this->state = (uint64_t*)calloc(this->nb, sizeof(uint64_t));
    if (this->state == NULL)
        perror("Could not allocate memory for cipher state.");

    this->round_keys = (uint64_t**)calloc(this->nr + 1, sizeof(uint64_t**));
    if (this->round_keys == NULL) 
        perror("Could not allocate memory for cipher round keys.");

    for (i = 0; i < this->nr + 1; ++i) {
        this->round_keys[i] = (uint64_t*)calloc(this->nb, sizeof(uint64_t));
        if (this->round_keys[i] == NULL)
            perror("Could not allocate memory for cipher round keys.");
    }
}

void Kalyna::SubBytes() {
    int i;
    uint64_t* s = this->state; /* For shorter expressions. */
    for (i = 0; i < this->nb; ++i) {
        this->state[i] = sboxes_enc[0][s[i] & 0x00000000000000FFULL] |
            ((uint64_t)sboxes_enc[1][(s[i] & 0x000000000000FF00ULL) >> 8] << 8) |
            ((uint64_t)sboxes_enc[2][(s[i] & 0x0000000000FF0000ULL) >> 16] << 16) |
            ((uint64_t)sboxes_enc[3][(s[i] & 0x00000000FF000000ULL) >> 24] << 24) |
            ((uint64_t)sboxes_enc[0][(s[i] & 0x000000FF00000000ULL) >> 32] << 32) |
            ((uint64_t)sboxes_enc[1][(s[i] & 0x0000FF0000000000ULL) >> 40] << 40) |
            ((uint64_t)sboxes_enc[2][(s[i] & 0x00FF000000000000ULL) >> 48] << 48) |
            ((uint64_t)sboxes_enc[3][(s[i] & 0xFF00000000000000ULL) >> 56] << 56);
    }
}

void Kalyna::InvSubBytes() {
    int i;
    uint64_t* s = this->state; /* For shorter expressions. */
    for (i = 0; i < this->nb; ++i) {
        this->state[i] = sboxes_dec[0][s[i] & 0x00000000000000FFULL] |
            ((uint64_t)sboxes_dec[1][(s[i] & 0x000000000000FF00ULL) >> 8] << 8) |
            ((uint64_t)sboxes_dec[2][(s[i] & 0x0000000000FF0000ULL) >> 16] << 16) |
            ((uint64_t)sboxes_dec[3][(s[i] & 0x00000000FF000000ULL) >> 24] << 24) |
            ((uint64_t)sboxes_dec[0][(s[i] & 0x000000FF00000000ULL) >> 32] << 32) |
            ((uint64_t)sboxes_dec[1][(s[i] & 0x0000FF0000000000ULL) >> 40] << 40) |
            ((uint64_t)sboxes_dec[2][(s[i] & 0x00FF000000000000ULL) >> 48] << 48) |
            ((uint64_t)sboxes_dec[3][(s[i] & 0xFF00000000000000ULL) >> 56] << 56);
    }
}


void Kalyna::ShiftRows() {
    int row, col;
    int shift = -1;

    uint8_t* state = WordsToBytes(this->nb, this->state);
    uint8_t* nstate = (uint8_t*) malloc(this->nb * sizeof(uint64_t));

    for (row = 0; row < sizeof(uint64_t); ++row) {
        if (row % (sizeof(uint64_t) / this->nb) == 0)
            shift += 1;
        for (col = 0; col < this->nb; ++col) {
            INDEX(nstate, row, (col + shift) % this->nb) = INDEX(state, row, col);
        }
    }

    this->state = BytesToWords(this->nb * sizeof(uint64_t), nstate);
    free(state);
}

void Kalyna::InvShiftRows() {
    int row, col;
    int shift = -1;

    uint8_t* state = WordsToBytes(this->nb, this->state);
    uint8_t* nstate = (uint8_t*) malloc(this->nb * sizeof(uint64_t));

    for (row = 0; row < sizeof(uint64_t); ++row) {
        if (row % (sizeof(uint64_t) / this->nb) == 0)
            shift += 1;
        for (col = 0; col < this->nb; ++col) {
            INDEX(nstate, row, col) = INDEX(state, row, (col + shift) % this->nb);
        }
    }

    this->state = BytesToWords(this->nb * sizeof(uint64_t), nstate);
    free(state);
}


uint8_t Kalyna::MultiplyGF(uint8_t x, uint8_t y) {
    int i;
    uint8_t r = 0;
    uint8_t hbit = 0;
    for (i = 0; i < kBITS_IN_BYTE; ++i) {
        if ((y & 0x1) == 1)
            r ^= x;
        hbit = x & 0x80;
        x <<= 1;
        if (hbit == 0x80)
            x ^= kREDUCTION_POLYNOMIAL;
        y >>= 1;
    }
    return r;
}

void Kalyna::MatrixMultiply(uint8_t matrix[8][8]) {
    int col, row, b;
    uint8_t product;
    uint64_t result;
    uint8_t* state = WordsToBytes(this->nb, this->state);

    for (col = 0; col < this->nb; ++col) {
        result = 0;
        for (row = sizeof(uint64_t) - 1; row >= 0; --row) {
            product = 0;
            for (b = sizeof(uint64_t) - 1; b >= 0; --b) {
                product ^= MultiplyGF(INDEX(state, b, col), matrix[row][b]);
            }
            result |= (uint64_t)product << (row * sizeof(uint64_t));
        }    
        this->state[col] = result;
    }
}

void Kalyna::MixColumns() {
    MatrixMultiply(mds_matrix);
}

void Kalyna::InvMixColumns() {
    MatrixMultiply(mds_inv_matrix);
}


void Kalyna::EncryptRound() {
    SubBytes();
    ShiftRows();
    MixColumns();
}

void Kalyna::DecryptRound() {
    InvMixColumns();
    InvShiftRows();
    InvSubBytes();
}

void Kalyna::AddRoundKey(int round) {
    int i;
    for (i = 0; i < this->nb; ++i) {
        this->state[i] = this->state[i] + this->round_keys[round][i];
    }
}

void Kalyna::SubRoundKey(int round) {
    int i;
    for (i = 0; i < this->nb; ++i) {
        this->state[i] = this->state[i] - this->round_keys[round][i];
    }
}


void Kalyna::AddRoundKeyExpand(uint64_t* value) {
    int i;
    for (i = 0; i < this->nb; ++i) {
        this->state[i] = this->state[i] + value[i];
    }
}


void Kalyna::XorRoundKey(int round) {
    int i;
    for (i = 0; i < this->nb; ++i) {
        this->state[i] = this->state[i] ^ this->round_keys[round][i];
    }
}


void Kalyna::XorRoundKeyExpand(uint64_t* value) {
    int i;
    for (i = 0; i < this->nb; ++i) {
        this->state[i] = this->state[i] ^ value[i];
    }
}


void Kalyna::Rotate(size_t state_size, uint64_t* state_value) {
    int i;
    uint64_t temp = state_value[0];
    for (i = 1; i < state_size; ++i) {
        state_value[i - 1] = state_value[i];
    }
    state_value[state_size - 1] = temp;
}


void Kalyna::ShiftLeft(size_t state_size, uint64_t* state_value) {
    int i;
    for (i = 0; i < state_size; ++i) {
        state_value[i] <<= 1;
    } 
}

void Kalyna::RotateLeft(size_t state_size, uint64_t* state_value) {
    size_t rotate_bytes = 2 * state_size + 3;
    size_t bytes_num = state_size * (kBITS_IN_WORD / kBITS_IN_BYTE);

    uint8_t* bytes = WordsToBytes(state_size, state_value);
    uint8_t* buffer = (uint8_t*) malloc(rotate_bytes);

    memcpy(buffer, bytes, rotate_bytes);
    memmove(bytes, bytes + rotate_bytes, bytes_num - rotate_bytes);
    memcpy(bytes + bytes_num - rotate_bytes, buffer, rotate_bytes);

    state_value = BytesToWords(bytes_num, bytes);

    free(buffer);
}


void Kalyna::KeyExpandKt(uint64_t* key, uint64_t* kt) {
    uint64_t* k0 = (uint64_t*) malloc(this->nb * sizeof(uint64_t));
    uint64_t* k1 = (uint64_t*) malloc(this->nb * sizeof(uint64_t));
	
	memset(this->state, 0, this->nb * sizeof(uint64_t));
    this->state[0] += this->nb + this->nk + 1;
	   
    if (this->nb == this->nk) {
        memcpy(k0, key, this->nb * sizeof(uint64_t));
        memcpy(k1, key, this->nb * sizeof(uint64_t));
    } else {
        memcpy(k0, key, this->nb * sizeof(uint64_t));
        memcpy(k1, key + this->nb, this->nb * sizeof(uint64_t));
    }

    AddRoundKeyExpand(k0);
    EncryptRound();
    XorRoundKeyExpand(k1);
    EncryptRound();
    AddRoundKeyExpand(k0);
    EncryptRound();
    memcpy(kt, this->state, this->nb * sizeof(uint64_t));

    free(k0);
    free(k1);
}


void Kalyna::KeyExpandEven(uint64_t* key, uint64_t* kt) {
    int i;
    uint64_t* initial_data = (uint64_t*) malloc(this->nk * sizeof(uint64_t));
    uint64_t* kt_round = (uint64_t*) malloc(this->nb * sizeof(uint64_t));
    uint64_t* tmv = (uint64_t*) malloc(this->nb * sizeof(uint64_t));
	size_t round = 0;

    memcpy(initial_data, key, this->nk * sizeof(uint64_t));
    for (i = 0; i < this->nb; ++i) {
        tmv[i] = 0x0001000100010001;
    }

    while(TRUE) {
        memcpy(this->state, kt, this->nb * sizeof(uint64_t));
        AddRoundKeyExpand(tmv);
        memcpy(kt_round, this->state, this->nb * sizeof(uint64_t));

        memcpy(this->state, initial_data, this->nb * sizeof(uint64_t));

        AddRoundKeyExpand(kt_round);
        EncryptRound();
        XorRoundKeyExpand(kt_round);
        EncryptRound();
        AddRoundKeyExpand(kt_round);

        memcpy(this->round_keys[round], this->state, this->nb * sizeof(uint64_t));

        if (this->nr == round)
            break;

        if (this->nk != this->nb) {
            round += 2;

            ShiftLeft(this->nb, tmv);

            memcpy(this->state, kt, this->nb * sizeof(uint64_t));
            AddRoundKeyExpand(tmv);
            memcpy(kt_round, this->state, this->nb * sizeof(uint64_t));

            memcpy(this->state, initial_data + this->nb, this->nb * sizeof(uint64_t));

            AddRoundKeyExpand(kt_round);
            EncryptRound();
            XorRoundKeyExpand(kt_round);
            EncryptRound();
            AddRoundKeyExpand(kt_round);

            memcpy(this->round_keys[round], this->state, this->nb * sizeof(uint64_t));

            if (this->nr == round)
                break;
        }
        round += 2;
        ShiftLeft(this->nb, tmv);
        Rotate(this->nk, initial_data);
    }

    free(initial_data);
    free(kt_round);
    free(tmv);
}

void Kalyna::KeyExpandOdd() {
    int i;
    for (i = 1; i < this->nr; i += 2) {
        memcpy(this->round_keys[i], this->round_keys[i - 1], this->nb * sizeof(uint64_t));
        RotateLeft(this->nb, this->round_keys[i]);
    }
}

void Kalyna::KeyExpansion(uint64_t* key) {
    uint64_t* kt = (uint64_t*) malloc(this->nb * sizeof(uint64_t));
    KeyExpandKt(key, kt);
    KeyExpandEven(key, kt);
    KeyExpandOdd();
    free(kt);
}


void Kalyna::Encrypt(uint64_t* plaintext, uint64_t* ciphertext) {
    int round = 0;
    memcpy(this->state, plaintext, this->nb * sizeof(uint64_t));

    AddRoundKey(round);
    for (round = 1; round < this->nr; ++round) {
        EncryptRound();
        XorRoundKey(round);
    }
    EncryptRound();
    AddRoundKey(this->nr);

    memcpy(ciphertext, this->state, this->nb * sizeof(uint64_t));
}

void Kalyna::Decrypt(uint64_t* ciphertext, uint64_t* plaintext) {
    int round = this->nr;
    memcpy(this->state, ciphertext, this->nb * sizeof(uint64_t));

    SubRoundKey(round);
    for (round = this->nr - 1; round > 0; --round) {
        DecryptRound();
        XorRoundKey(round);
    }
    DecryptRound();
    SubRoundKey(0);

    memcpy(plaintext, this->state, this->nb * sizeof(uint64_t));
}


uint8_t* Kalyna::WordsToBytes(size_t length, uint64_t* words) {
    int i;
	uint8_t* bytes;
    if (IsBigEndian()) {
        for (i = 0; i < length; ++i) {
            words[i] = ReverseWord(words[i]);
        }        
    }
    bytes = (uint8_t*)words;
    return bytes;
}

uint64_t* Kalyna::BytesToWords(size_t length, uint8_t* bytes) {
    int i;
    uint64_t* words = (uint64_t*)bytes;
    if (IsBigEndian()) {
        for (i = 0; i < length; ++i) {
            words[i] = ReverseWord(words[i]);
        }        
    }
    return words;
}


uint64_t Kalyna::ReverseWord(uint64_t word) {
    int i;
    uint64_t reversed = 0;
    uint8_t* src = (uint8_t*)&word;
    uint8_t* dst = (uint8_t*)&reversed;

    for (i = 0; i < sizeof(uint64_t); ++i) {
        dst[i] = src[sizeof(uint64_t) - i];    
    }
    return reversed;
}


int Kalyna::IsBigEndian() {
    unsigned int num = 1;
    /* Check the least significant byte value to determine endianness */
    return (*((uint8_t*)&num) == 0);
}

void Kalyna::PrintState(size_t length, uint64_t* state) {
    int i;
    for (i = length - 1; i >= 0; --i) {
        printf("%16.16lx", state[i]);
    } 
    printf("\n");
}

std::string Kalyna::BytesToString(uint8_t* bytes)
{
    std::string converted(reinterpret_cast<char*>(bytes));
    return converted;
}

uint64_t* Kalyna::StringToWords(std::string in_str, int& len)
{
    uint8_t* in_arr = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(in_str.c_str()));
    size_t inLen = in_str.size();
    uint64_t* words = BytesToWords(inLen, in_arr);
    return words;
}

uint64_t* Kalyna::EncryptString(std::string plaintext, uint64_t* key, int& outLen)
{
    outLen = plaintext.size() / 8;
    if (plaintext.size() % 8 != 0)
    {
        outLen = outLen + 1;
    }
    if (outLen % nb != 0)
    {
        std::cout << outLen << " Danger Zone, be careful\n";
    }
    uint64_t* in_words = StringToWords(plaintext, outLen);
    uint64_t* out_words = new uint64_t[outLen];
    KeyExpansion(key);
    for (int i = 0; i < outLen; i += nb)
    {
        Encrypt(in_words+i, out_words+i);
    }
    delete[] in_words;
    return out_words;
}

uint64_t* Kalyna::DecryptString(uint64_t* ciphertext, uint64_t* key, int inLen)
{
    uint64_t* out = new uint64_t[inLen];
    KeyExpansion(key);
    for (int i = 0; i < inLen; i += nb)
    {
        Decrypt(ciphertext + i, out + i);
    }
    return out;
}