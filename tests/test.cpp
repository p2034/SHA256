#include <iostream>
#include <stdexcept>

#include "sha256.h"


int main() {
  try {
    SHA256 sha256;

    std::string str = "hello world";
    //std::cin >> str;
    uint64_t size = str.length();
    uint8_t* arr = new uint8_t[size];

    for (int i = 0; i < size; i++)
      arr[i] = str[i];

    std::string hash = sha256.get_str(arr, size);

    std::cout << hash << std::endl;

  } catch(const std::exception& excpt) {
    std::cout << excpt.what() << "\n";
  }

	return 0;
}