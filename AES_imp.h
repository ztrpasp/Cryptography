#include "AES.h"
AES::AES(const AESKeyLength keyLength) {
  switch (keyLength) {
    case AESKeyLength::AES_128:
      this->Nk = 4;
      this->Nr = 10;
      break;
    case AESKeyLength::AES_192:
      this->Nk = 6;
      this->Nr = 12;
      break;
    case AESKeyLength::AES_256:
      this->Nk = 8;
      this->Nr = 14;
      break;
  }
}

unsigned char *AES::EncryptECB(unsigned char in[], unsigned int inLen,
                               unsigned char key[]) {
  CheckLength(inLen);
  unsigned char *out = new unsigned char[inLen];
  unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
    EncryptBlock(in + i, out + i, roundKeys);
  }

  delete[] roundKeys;

  return out;
}

unsigned char *AES::DecryptECB(unsigned char in[], unsigned int inLen,
                               unsigned char key[]) {
  CheckLength(inLen);
  unsigned char *out = new unsigned char[inLen];
  unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
    DecryptBlock(in + i, out + i, roundKeys);
  }

  delete[] roundKeys;

  return out;
}

unsigned char *AES::EncryptCBC(unsigned char in[], unsigned int inLen,
                               unsigned char key[],
                               unsigned char *iv) {
  CheckLength(inLen);
  unsigned char *out = new unsigned char[inLen];
  unsigned char block[blockBytesLen];
  unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
    XorBlocks(block, in + i, block, blockBytesLen);
    EncryptBlock(block, out + i, roundKeys);
    memcpy(block, out + i, blockBytesLen);
  }

  delete[] roundKeys;

  return out;
}

unsigned char *AES::DecryptCBC(unsigned char in[], unsigned int inLen,
                               unsigned char key[],
                               unsigned char *iv) {
  CheckLength(inLen);
  unsigned char *out = new unsigned char[inLen];
  unsigned char block[blockBytesLen];
  unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
    DecryptBlock(in + i, out + i, roundKeys);
    XorBlocks(block, out + i, out + i, blockBytesLen);
    memcpy(block, in + i, blockBytesLen);
  }

  delete[] roundKeys;

  return out;
}



void AES::CheckLength(unsigned int len) {
  if (len % blockBytesLen != 0) {
    throw std::length_error("Plaintext length must be divisible by " +
                            std::to_string(blockBytesLen));
  }
}

void AES::EncryptBlock(const unsigned char in[], unsigned char out[],
                       unsigned char *roundKeys) {
  unsigned char state[4][Nb];
  unsigned int i, j, round;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      state[i][j] = in[i + 4 * j];
    }
  }

  AddRoundKey(state, roundKeys);

  for (round = 1; round <= Nr - 1; round++) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, roundKeys + round * 4 * Nb);
  }

  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(state, roundKeys + Nr * 4 * Nb);

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      out[i + 4 * j] = state[i][j];
    }
  }
}

void AES::DecryptBlock(const unsigned char in[], unsigned char out[],
                       unsigned char *roundKeys) {
  unsigned char state[4][Nb];
  unsigned int i, j, round;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      state[i][j] = in[i + 4 * j];
    }
  }

  AddRoundKey(state, roundKeys + Nr * 4 * Nb);

  for (round = Nr - 1; round >= 1; round--) {
    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state, roundKeys + round * 4 * Nb);
    InvMixColumns(state);
  }

  InvSubBytes(state);
  InvShiftRows(state);
  AddRoundKey(state, roundKeys);

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      out[i + 4 * j] = state[i][j];
    }
  }
}

void AES::SubBytes(unsigned char state[4][Nb]) {
  unsigned int i, j;
  unsigned char t;
  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      t = state[i][j];
      state[i][j] = sbox[t / 16][t % 16];
    }
  }
}

void AES::ShiftRow(unsigned char state[4][Nb], unsigned int i,
                   unsigned int n)  // shift row i on n positions
{
  unsigned char tmp[Nb];
  for (unsigned int j = 0; j < Nb; j++) {
    tmp[j] = state[i][(j + n) % Nb];
  }
  memcpy(state[i], tmp, Nb * sizeof(unsigned char));
}

void AES::ShiftRows(unsigned char state[4][Nb]) {
  ShiftRow(state, 1, 1);
  ShiftRow(state, 2, 2);
  ShiftRow(state, 3, 3);
}

unsigned char AES::xtime(unsigned char b)  // multiply on x
{
  return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}

void AES::MixColumns(unsigned char state[4][Nb]) {
  unsigned char temp_state[4][Nb];

  for (size_t i = 0; i < 4; ++i) {
    memset(temp_state[i], 0, 4);
  }

  for (size_t i = 0; i < 4; ++i) {
    for (size_t k = 0; k < 4; ++k) {
      for (size_t j = 0; j < 4; ++j) {
        if (CMDS[i][k] == 1)
          temp_state[i][j] ^= state[k][j];
        else
          temp_state[i][j] ^= GF_MUL_TABLE[CMDS[i][k]][state[k][j]];
      }
    }
  }

  for (size_t i = 0; i < 4; ++i) {
    memcpy(state[i], temp_state[i], 4);
  }
}

void AES::AddRoundKey(unsigned char state[4][Nb], unsigned char *key) {
  unsigned int i, j;
  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      state[i][j] = state[i][j] ^ key[i + 4 * j];
    }
  }
}

void AES::SubWord(unsigned char *a) {
  int i;
  for (i = 0; i < 4; i++) {
    a[i] = sbox[a[i] / 16][a[i] % 16];
  }
}

void AES::RotWord(unsigned char *a) {
  unsigned char c = a[0];
  a[0] = a[1];
  a[1] = a[2];
  a[2] = a[3];
  a[3] = c;
}

void AES::XorWords(unsigned char *a, unsigned char *b, unsigned char *c) {
  int i;
  for (i = 0; i < 4; i++) {
    c[i] = a[i] ^ b[i];
  }
}

void AES::Rcon(unsigned char *a, unsigned int n) {
  unsigned int i;
  unsigned char c = 1;
  for (i = 0; i < n - 1; i++) {
    c = xtime(c);
  }

  a[0] = c;
  a[1] = a[2] = a[3] = 0;
}

void AES::KeyExpansion(const unsigned char key[], unsigned char w[]) {
  unsigned char temp[4];
  unsigned char rcon[4];

  unsigned int i = 0;
  while (i < 4 * Nk) {
    w[i] = key[i];
    i++;
  }

  i = 4 * Nk;
  while (i < 4 * Nb * (Nr + 1)) {
    temp[0] = w[i - 4 + 0];
    temp[1] = w[i - 4 + 1];
    temp[2] = w[i - 4 + 2];
    temp[3] = w[i - 4 + 3];

    if (i / 4 % Nk == 0) {
      RotWord(temp);
      SubWord(temp);
      Rcon(rcon, i / (Nk * 4));
      XorWords(temp, rcon, temp);
    } else if (Nk > 6 && i / 4 % Nk == 4) {
      SubWord(temp);
    }

    w[i + 0] = w[i - 4 * Nk] ^ temp[0];
    w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
    w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
    w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
    i += 4;
  }
}

void AES::InvSubBytes(unsigned char state[4][Nb]) {
  unsigned int i, j;
  unsigned char t;
  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      t = state[i][j];
      state[i][j] = inv_sbox[t / 16][t % 16];
    }
  }
}

void AES::InvMixColumns(unsigned char state[4][Nb]) {
  unsigned char temp_state[4][Nb];

  for (size_t i = 0; i < 4; ++i) {
    memset(temp_state[i], 0, 4);
  }

  for (size_t i = 0; i < 4; ++i) {
    for (size_t k = 0; k < 4; ++k) {
      for (size_t j = 0; j < 4; ++j) {
        temp_state[i][j] ^= GF_MUL_TABLE[INV_CMDS[i][k]][state[k][j]];
      }
    }
  }

  for (size_t i = 0; i < 4; ++i) {
    memcpy(state[i], temp_state[i], 4);
  }
}

void AES::InvShiftRows(unsigned char state[4][Nb]) {
  ShiftRow(state, 1, Nb - 1);
  ShiftRow(state, 2, Nb - 2);
  ShiftRow(state, 3, Nb - 3);
}

void AES::XorBlocks(const unsigned char *a, const unsigned char *b,
                    unsigned char *c, unsigned int len) {
  for (unsigned int i = 0; i < len; i++) {
    c[i] = a[i] ^ b[i];
  }
}

// void AES::printHexArray(unsigned char a[], unsigned int n) {
//   for (unsigned int i = 0; i < n; i++) {
//     printf("%02x ", a[i]);
//   }
// }

void printStr(unsigned char *in,int length)
{
  for(int i=1; i<=length; i++)
  {
    printf("0x%02X ",in[i-1]);
    if(i % 16 == 0){
			printf("\n");
		}
  }
  
}

unsigned char key[16];
void AES::setKey(string AESKey)
{
  for(int i=0; i<16; i++)
  {
    key[i] = AESKey[i];
    cout<<key[i]<<" ";
  }
}
char * AES::encode(char buffer[1024],int length)
{
  unsigned int plainLen = length * sizeof(unsigned char);
  if(plainLen % 16 != 0)
  {
    plainLen += (16-plainLen % 16);
  }
  unsigned char* out = this->EncryptECB((unsigned char *)buffer, plainLen, key);
  memset(buffer,0,1024);
  for(int i=0; i<plainLen; i++)
  {
    buffer[i]=out[i];
  }
  return (char *)buffer;
}
char * AES::decode(char buffer[1024])
{
  string s = buffer;
  cout<<"收到的密文信息"<<endl;
  printStr((unsigned char*)buffer,s.size());
  unsigned char * out = DecryptECB((unsigned char*)buffer, s.size(), key);
  cout<<"解密后的明文信息"<<endl;
  cout<<out<<endl;
}

// int main()
// {
//   char plain[1024];
//   cin>>plain;
//   int len = strlen(plain);
//   cout<<len<<endl;


//   cout<<plain<<endl;
//   int plainLen = (len+1) * sizeof(unsigned char);  //bytes in plaintext
//   //unsigned char key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; //key example
  

  

//   AES aes(AESKeyLength::AES_128);  ////128 - key length, can be 128, 192 or 256
//   char* out = aes.encode(plain,plainLen);

//   out = aes.decode(out);
//   system("pause");
//   return 0;
// }