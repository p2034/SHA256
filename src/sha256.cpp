// Copyright (c) 2021 Kandakov Danil (p2034 or the_lll_end)
// https://github.com/p2034



/**
 * @file
 * @brief sha256 implementation
 */

// for std::string output
#include <string>
#include <iomanip>
#include <sstream>

#include <cstring>
#include <cstdint>
#include <limits.h>   // for CHAR_BIT

#include "sha256.h"



// https://stackoverflow.com/questions/776508/best-practices-for-circular-shift-rotate-operations-in-c
inline uint32_t SHA256::rightrotate(uint32_t n, unsigned int c) const {
  const unsigned int mask = (CHAR_BIT*sizeof(n) - 1);
  // assert ( (c<=mask) &&"rotate by type width or more");
  c &= mask;
  return (n>>c) | (n<<( (-c)&mask ));
}



uint8_t* SHA256::preprocessor(const uint8_t* data, uint64_t size, uint64_t& newSize) const {
  newSize = size + 1 + SHA256_BLOCK_SIZE - ((size + 1) % SHA256_BLOCK_SIZE);

  uint8_t* newArray = new uint8_t[newSize];
  // set it to 10000000
  newArray[size] = SHA256_FIRST_ADDED_BYTE;
  // copy data
  std::memcpy(newArray, data, size * sizeof(uint8_t));
  // set bits to 0
  for (int i = size + 1; i < newSize; i++)
    newArray[i] = 0;

  // set size of array in the end
  uint64_t writedSize = size * 8;
  for (int i = 0; i < 4; i++)
    std::memcpy(&(newArray[newSize - 1 - i]), reinterpret_cast<uint8_t*>(&writedSize) + i, sizeof(uint8_t));

  return newArray;
}



uint8_t* SHA256::get(const uint8_t* data, uint64_t size) const {
  uint8_t* eData; ///< adding up to 512 bits
  uint64_t newSize; ///< size of exteded data, newSize % 512 = 0

  // set '1' and lots of '0' with size in the end
  eData = this->preprocessor(data, size, newSize);

  // get constants for process
  uint32_t h[SHA256_SQRT_NUM];
  for (int i = 0; i < SHA256_SQRT_NUM; i++)
    h[i] = h_[i];

  int numOfChunks = newSize / SHA256_BLOCK_SIZE;

  // chunk processor
  for (int y = 0; y < numOfChunks; y++) {
    uint32_t* eeData = new uint32_t[SHA256_BLOCK_SIZE]; ///< data extended one more time
    // copy chunk, very strange way because of big-endian order in sha256
    for (int i = 0; i < 16; i++)
      for (int j = 0; j < 4; j++)
        std::memcpy((reinterpret_cast<uint8_t*>(eeData) + i*4 + j),
                    &(eData[y * SHA256_BLOCK_SIZE + i*4 + 3 - j]), sizeof(uint8_t));

    // extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
    for (int i = (SHA256_BLOCK_SIZE / DIFFERENCE_32_8); i < SHA256_BLOCK_SIZE; i++) {
      uint32_t s0 = rightrotate(eeData[i - 15], 7) ^ rightrotate(eeData[i - 15], 18) ^ (eeData[i - 15] >> 3);
      uint32_t s1 = rightrotate(eeData[i - 2], 17) ^ rightrotate(eeData[i - 2], 19) ^ (eeData[i - 2] >> 10);
      eeData[i] = eeData[i - 16] + s0 + eeData[i - 7] + s1;
    }

    // init a[] array
    uint32_t a[SHA256_SQRT_NUM];
    for (int i = 0; i < SHA256_SQRT_NUM; i++)
      a[i] = h[i];

    // compression function main loop
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
      uint32_t s1 = rightrotate(a[4], 6) ^ rightrotate(a[4], 11) ^ rightrotate(a[4], 25);
      uint32_t ch = (a[4] & a[5]) ^ ((~a[4]) & a[6]);
      uint32_t temp1 = a[7] + s1 + ch + k_[i] + eeData[i];

      uint32_t s0 = rightrotate(a[0], 2) ^ rightrotate(a[0], 13) ^ rightrotate(a[0], 22);
      uint32_t maj = (a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]);
      uint32_t temp2 = s0 + maj;

      // set a[] array
      a[7] = a[6];
      a[6] = a[5];
      a[5] = a[4];
      a[4] = a[3] + temp1;
      a[3] = a[2];
      a[2] = a[1];
      a[1] = a[0];
      a[0] = temp1 + temp2;
    }

    // add a[] array to h[] array
    for (int j = 0; j < SHA256_SQRT_NUM; j++)
      h[j] = h[j] + a[j];

    delete[] eeData;
  }
  
  delete[] eData;

  uint8_t* hash = new uint8_t[SHA256_HASH_SIZE];
  for (int i = 0; i < SHA256_SQRT_NUM; i++)
    for (int j = 0; j < 4; j++)
      std::memcpy(&(hash[i * DIFFERENCE_32_8 + j]), reinterpret_cast<uint8_t*>(&h[i]) + 3 - j, sizeof(uint32_t));

  return hash;
}



std::string SHA256::get_str(const uint8_t* data, uint64_t size) const {
  uint8_t* hash = this->get(data, size);

  std::stringstream s;
	s << std::setfill('0') << std::hex;
	for(uint8_t i = 0 ; i < 32 ; i++)
		s << std::setw(2) << (unsigned int) hash[i];

  return s.str();
}