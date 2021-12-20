#include "AES.h"

AES::AES(int keyLength)
{
    this->Nb = 4;
    switch (keyLength)
    {
    case 128:
        this->Nk = 4;
        this->Nr = 10;
        break;
    case 192:
        this->Nk = 6;
        this->Nr = 12;
        break;
    case 256:
        this->Nk = 8;
        this->Nr = 14;
        break;
    default:
        std::cout << "Incorrect key length. Please use 128, 192 or 256\n";
    }
}


uint8_t* AES::Encrypt(const uint8_t in[], unsigned int inLen, uint8_t key[], unsigned int &outLen)
{
    outLen = GetPaddingLength(inLen);
    uint8_t *alignIn  = PaddingNulls(in, inLen, outLen);
    uint8_t *out = new uint8_t[outLen];
    uint8_t *roundKeys = new uint8_t[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    for (unsigned int i = 0; i < outLen; i+= 4 * Nb)
    {
        EncryptBlock(alignIn + i, out + i, roundKeys);
    }
    
    delete[] alignIn;
    delete[] roundKeys;
    
    return out;
}

uint8_t* AES::Decrypt(const uint8_t in[], unsigned int inLen, uint8_t key[])
{
    uint8_t *out = new uint8_t[inLen];
    uint8_t *roundKeys = new uint8_t[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    for (unsigned int i = 0; i < inLen; i+= 4 * Nb)
    {
        DecryptBlock(in + i, out + i, roundKeys);
    }

    delete[] roundKeys;
    return out;
}

uint8_t* AES::Encrypt(string in, uint8_t key[], unsigned int &outLen)
{
    const uint8_t* in_arr = reinterpret_cast<const uint8_t*>(in.c_str());
    unsigned int inLen = in.size();
    return Encrypt(in_arr, inLen, key, outLen);
}

uint8_t* AES::Decrypt(string in, uint8_t key[])
{
    const uint8_t* in_arr = reinterpret_cast<const uint8_t*>(in.c_str());
    unsigned int inLen = in.size();
    return Decrypt(in_arr, inLen, key);
}

uint8_t* AES::PaddingNulls(const uint8_t in[], unsigned int inLen, unsigned int alignLen)
{
    uint8_t *alignIn = new uint8_t[alignLen];
    memcpy(alignIn, in, inLen);
    memset(alignIn + inLen, 0x00, alignLen - inLen);
    return alignIn;
}

unsigned int AES::GetPaddingLength(unsigned int len)
{
    unsigned int lengthWithPadding =  (len / (4 * Nb));
    if (len % (4 * Nb)) {
        lengthWithPadding++;
    }
    
    lengthWithPadding *=  4 * Nb;
    
    return lengthWithPadding;
}

void AES::EncryptBlock(const uint8_t in[], uint8_t out[], uint8_t *roundKeys)
{
    uint8_t **state = new uint8_t *[4];
    state[0] = new uint8_t[4 * Nb];
    int i, j, round;
    for (i = 0; i < 4; i++)
    {
        state[i] = state[0] + Nb * i;
    }


    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
        state[i][j] = in[i + 4 * j];
        }
    }

    AddRoundKey(state, roundKeys);

    for (round = 1; round <= Nr - 1; round++)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * 4 * Nb);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + Nr * 4 * Nb);

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            out[i + 4 * j] = state[i][j];
        }
    }

    delete[] state[0];
    delete[] state;
}

void AES::DecryptBlock(const uint8_t in[], uint8_t out[],uint8_t *roundKeys)
{
    uint8_t **state = new uint8_t *[4];
    state[0] = new uint8_t[4 * Nb];
    int i, j, round;
    for (i = 0; i < 4; i++)
    {
        state[i] = state[0] + Nb * i;
    }


    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++) {
        state[i][j] = in[i + 4 * j];
        }
    }

    AddRoundKey(state, roundKeys + Nr * 4 * Nb);

    for (round = Nr - 1; round >= 1; round--)
    {
        InvSubBytes(state);
        InvShiftRows(state);
        AddRoundKey(state, roundKeys + round * 4 * Nb);
        InvMixColumns(state);
    }

    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state, roundKeys);

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++) {
            out[i + 4 * j] = state[i][j];
        }
    }

    delete[] state[0];
    delete[] state;
}


void AES::SubBytes(uint8_t **state)
{
    int i, j;
    uint8_t t;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            t = state[i][j];
            state[i][j] = sbox[t / 16][t % 16];
        }
    }

}

void AES::ShiftRow(uint8_t **state, int i, int n)    // shift row i on n positions
{
    uint8_t *tmp = new uint8_t[Nb];
    for (int j = 0; j < Nb; j++) {
        tmp[j] = state[i][(j + n) % Nb];
    }
    memcpy(state[i], tmp, Nb * sizeof(uint8_t));
        
    delete[] tmp;
}

void AES::ShiftRows(uint8_t **state)
{
    ShiftRow(state, 1, 1);
    ShiftRow(state, 2, 2);
    ShiftRow(state, 3, 3);
}

uint8_t AES::xtime(uint8_t b)    // multiply on x
{
    return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}



void AES::MixColumns(uint8_t** state) 
{
    uint8_t temp_state[4][4];
    
    for(size_t i=0; i<4; ++i)
    {
        memset(temp_state[i],0,4);
    }

    for(size_t i=0; i<4; ++i)
    {
        for(size_t k=0; k<4; ++k)
        {
            for(size_t j=0; j<4; ++j)
            {
                if(CMDS[i][k]==1)
                    temp_state[i][j] ^= state[k][j];
                else
                    temp_state[i][j] ^= GF_MUL_TABLE[CMDS[i][k]][state[k][j]];
            }
        }
    }

    for(size_t i=0; i<4; ++i)
    {
        memcpy(state[i],temp_state[i],4);
    }
}

void AES::AddRoundKey(uint8_t **state, uint8_t *key)
{
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            state[i][j] = state[i][j] ^ key[i + 4 * j];
        }
    }
}

void AES::SubWord(uint8_t *a)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        a[i] = sbox[a[i] / 16][a[i] % 16];
    }
}

void AES::RotWord(uint8_t *a)
{
    uint8_t c = a[0];
    a[0] = a[1];
    a[1] = a[2];
    a[2] = a[3];
    a[3] = c;
}

void AES::XorWords(uint8_t *a, uint8_t *b, uint8_t *c)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        c[i] = a[i] ^ b[i];
    }
}

void AES::Rcon(uint8_t * a, int n)
{
    int i;
    uint8_t c = 1;
    for (i = 0; i < n - 1; i++)
    {
        c = xtime(c);
    }

    a[0] = c;
    a[1] = a[2] = a[3] = 0;
}

void AES::KeyExpansion(uint8_t key[], uint8_t w[])
{
    uint8_t *temp = new uint8_t[4];
    uint8_t *rcon = new uint8_t[4];

    int i = 0;
    while (i < 4 * Nk)
    {
        w[i] = key[i];
        i++;
    }

    i = 4 * Nk;
    while (i < 4 * Nb * (Nr + 1))
    {
        temp[0] = w[i - 4 + 0];
        temp[1] = w[i - 4 + 1];
        temp[2] = w[i - 4 + 2];
        temp[3] = w[i - 4 + 3];

        if (i / 4 % Nk == 0)
        {
            RotWord(temp);
            SubWord(temp);
            Rcon(rcon, i / (Nk * 4));
            XorWords(temp, rcon, temp);
        }
        else if (Nk > 6 && i / 4 % Nk == 4)
        {
            SubWord(temp);
        }

        w[i + 0] = w[i - 4 * Nk] ^ temp[0];
        w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
        w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
        w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
        i += 4;
    }

    delete []rcon;
    delete []temp;
}

void AES::InvSubBytes(uint8_t **state)
{
    int i, j;
    uint8_t t;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            t = state[i][j];
            state[i][j] = inv_sbox[t / 16][t % 16];
        }
    }
}



void AES::InvMixColumns(uint8_t **state)
{
    uint8_t temp_state[4][4];
    
    for(size_t i=0; i<4; ++i)
    {
        memset(temp_state[i],0,4);
    }

    for(size_t i=0; i<4; ++i)
    {
        for(size_t k=0; k<4; ++k)
        {
            for(size_t j=0; j<4; ++j)
            {
                temp_state[i][j] ^= GF_MUL_TABLE[INV_CMDS[i][k]][state[k][j]];
            }
        }
    }

    for(size_t i=0; i<4; ++i)
    {
        memcpy(state[i],temp_state[i],4);
    }
}

void AES::InvShiftRows(uint8_t **state)
{
    ShiftRow(state, 1, Nb - 1);
    ShiftRow(state, 2, Nb - 2);
    ShiftRow(state, 3, Nb - 3);
}

void AES::XorBlocks(uint8_t *a, uint8_t * b, uint8_t *c, unsigned int len)
{
    for (unsigned int i = 0; i < len; i++)
    {
        c[i] = a[i] ^ b[i];
    }
}

void AES::printHexArray (uint8_t a[], unsigned int n)
{
	for (unsigned int i = 0; i < n; i++) {
	    printf("%02x ", a[i]);
	}
}

void AES::printHexVector (vector<uint8_t> a)
{
	for (unsigned int i = 0; i < a.size(); i++) {
	    printf("%02x ", a[i]);
	}
}

vector<uint8_t> AES::ArrayToVector(uint8_t *a, uint8_t len)
{
    vector<uint8_t> v(a, a + len * sizeof(uint8_t));
    return v;
}

uint8_t *AES::VectorToArray(vector<uint8_t> a)
{
    return a.data();
}


vector<uint8_t> AES::Encrypt(vector<uint8_t> in, vector<uint8_t> key)
{
    unsigned int outLen = 0;;
    uint8_t *out = Encrypt(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key), outLen);
    vector<uint8_t> v = ArrayToVector(out, outLen);
    delete []out;
    return v;
}

vector<uint8_t> AES::Decrypt(vector<uint8_t> in, vector<uint8_t> key)
{
    uint8_t *out = Decrypt(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key));
    vector<uint8_t> v = ArrayToVector(out, (unsigned int)in.size());
    delete []out;
    return v;
}

string AES::ToString(uint8_t* data)
{
    string converted(reinterpret_cast<char*>(data));
    return converted;
}