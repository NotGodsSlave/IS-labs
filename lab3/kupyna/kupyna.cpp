#include<iostream>
#include "kupyna.h"
#include<cstring>
#include<iomanip>

Kupyna::Kupyna(size_t hashnbits)
{
    if (hashnbits <= 256)
    {
        this->rounds = NR_512;
        this->columns = NB_512;
        this->nbytes = STATE_BYTE_SIZE_512;
    }
    else {
        this->rounds = NR_1024;
        this->columns = NB_1024;
        this->nbytes = STATE_BYTE_SIZE_1024;
    }
    this->hash_nbits = hashnbits;

    memset(this->state, 0, this->nbytes);
    this->state[0][0] = this->nbytes;
}

void Kupyna::subBytes(uint8_t state[NB_1024][ROWS])
{
    uint8_t temp[NB_1024];
    for (int i = 0; i < ROWS; ++i) {
        for (int j = 0; j < columns; ++j) {
            state[j][i] = sboxes[i % 4][state[j][i]];
        }
    }
}

void Kupyna::shiftBytes(uint8_t state[NB_1024][ROWS])
{
    uint8_t temp[NB_1024];
    int shift = -1;
    for (int i = 0; i < ROWS; ++i) {
        if ((i == ROWS - 1) && (columns == NB_1024)) {
            shift = 11;
        } else {
            ++shift;
        }
        for (int j = 0; j < columns; ++j) {
            temp[(j + shift) % columns] = state[j][i];
        }
        for (int j = 0; j < columns; ++j) {
            state[j][i] = temp[j];
        }
    }
}

uint8_t Kupyna::multiplyGF(uint8_t x, uint8_t y)
{
    uint8_t r = 0;
    uint8_t hbit = 0;
    for (int i = 0; i < 8; ++i) {
        if ((y & 0x1) == 1)
            r ^= x;
        hbit = x & 0x80;
        x <<= 1;
        if (hbit == 0x80)
            x ^= Kupyna::REDUCTION_POLYNOMIAL;
        y >>= 1;
    }
    return r;
}

void Kupyna::mixColumns(uint8_t state[NB_1024][ROWS])
{
    uint8_t product;
    uint8_t result[ROWS];
    for (int col = 0; col < columns; ++col) {
        memset(result, ROWS, 0);
        for (int row = ROWS - 1; row >= 0; --row) {
            product = 0;
            for (int b = ROWS - 1; b >= 0; --b) {
                product ^= multiplyGF(state[col][b], mds_matrix[row][b]);
            }
            result[row] = product;
        }    
        for (int i = 0; i < ROWS; ++i) {
            state[col][i] = result[i];
        }
    }
}

void Kupyna::addRoundConstantP(uint8_t state[NB_1024][ROWS], int round)
{
    for (int i = 0; i < columns; ++i) {
        state[i][0] ^= (i * 0x10) ^ round;
    }
}

void Kupyna::addRoundConstantQ(uint8_t state[NB_1024][ROWS], int round)
{
    uint64_t* s = (uint64_t*)state;
    for (int j = 0; j < columns; ++j) {
        s[j] = s[j] + (0x00F0F0F0F0F0F0F3ULL ^ 
                ((((columns - j - 1) * 0x10ULL) ^ round) << (7 * 8)));
    }
}

void Kupyna::P(uint8_t state[NB_1024][ROWS])
{
    for (int i = 0; i < rounds; ++i) {
        addRoundConstantP(state, i);
        subBytes(state);
        shiftBytes(state);
        mixColumns(state);
    }
}

void Kupyna::Q(uint8_t state[NB_1024][ROWS])
{
    for (int i = 0; i < rounds; ++i) {
        addRoundConstantQ(state, i);
        subBytes(state);
        shiftBytes(state);
        mixColumns(state);
    }
}

void Kupyna::pad(const uint8_t* data, size_t msg_nbits)
{
    int mask, pad_bit;

    size_t msg_nbytes = msg_nbits / 8;
    size_t nblocks = msg_nbytes / nbytes;

    pad_nbytes = msg_nbytes - (nblocks * nbytes);
    data_nbytes = msg_nbytes - pad_nbytes;

    const uint8_t* pad_start = data + data_nbytes;
    int extra_bits = msg_nbits % 8;
    if (extra_bits) {
        pad_nbytes += 1;
    }

    memcpy(padding, pad_start, pad_nbytes);
    extra_bits = msg_nbits % 8;

    if (extra_bits) {
        mask = ~(0xFF >> (extra_bits));
        pad_bit = 1 << (7 - extra_bits);
        padding[pad_nbytes - 1] = (padding[pad_nbytes - 1] & mask) | pad_bit;
    } else {
        padding[pad_nbytes] = 0x80;
        pad_nbytes += 1;
    }

    int zero_nbytes = ((-msg_nbits - 97) % (nbytes * 8)) / 8;
    memset(padding + pad_nbytes, 0, zero_nbytes);
    pad_nbytes += zero_nbytes;
    for (int i = 0; i < (96 / 8); ++i, ++pad_nbytes) {
        if (i < sizeof(size_t)) {
            padding[pad_nbytes] = (msg_nbits >> (i * 8)) & 0xFF;
        } else {
            padding[pad_nbytes] = 0;
        }
    }
}

void Kupyna::digest(const uint8_t* data)
{
    uint8_t temp1[NB_1024][ROWS];
    uint8_t temp2[NB_1024][ROWS];
    for (int b = 0; b < data_nbytes; b += nbytes) {
        for (int i = 0; i < ROWS; ++i) {
            for (int j = 0; j < columns; ++j) {
                temp1[j][i] = state[j][i] ^ data[b + j * ROWS + i];
                temp2[j][i] = data[b + j * ROWS + i];
            }
        }
        P(temp1);
        Q(temp2);
        for (int i = 0; i < ROWS; ++i) {
            for (int j = 0; j < columns; ++j) {
                state[j][i] ^= temp1[j][i] ^ temp2[j][i];
            }
        }
    }
    /* Process extra bytes in padding. */
    for (int b = 0; b < pad_nbytes; b += nbytes) {
        for (int i = 0; i < ROWS; ++i) {
            for (int j = 0; j < columns; ++j) {
                temp1[j][i] = state[j][i] ^ padding[b + j * ROWS + i];
                temp2[j][i] = padding[b + j * ROWS + i];
            }
        }
        P(temp1);
        Q(temp2);
        for (int i = 0; i < ROWS; ++i) {
            for (int j = 0; j < columns; ++j) {
                state[j][i] ^= temp1[j][i] ^ temp2[j][i];
            }
        }
    }
}

void Kupyna::trunc(uint8_t* hashcode)
{
    size_t hash_nbytes = hash_nbits / 8;    
    memcpy(hashcode, (uint8_t*)state + nbytes - hash_nbytes, hash_nbytes);
}

void Kupyna::transformOutput(uint8_t* hashcode)
{
    uint8_t temp[NB_1024][ROWS];
    memcpy(temp, state, ROWS * NB_1024);
    P(temp);
    for (int i = 0; i < ROWS; ++i) {
        for (int j = 0; j < columns; ++j) {
            state[j][i] ^= temp[j][i];
        }
    }
    trunc(hashcode);
}

void Kupyna::hash(const uint8_t* data, size_t msg_nbits, uint8_t* hash)
{
    memset(state, 0, nbytes);
    state[0][0] = nbytes;

    pad(data, msg_nbits);
    digest(data);
    transformOutput(hash);
}

std::string Kupyna::toString(uint8_t *data) {
	std::stringstream s;
	s << std::setfill('0') << std::hex;

	for(uint8_t i = 0 ; i < 64; i++) {
		s << std::setw(2) << (unsigned int) data[i];
	}

	return s.str();
}