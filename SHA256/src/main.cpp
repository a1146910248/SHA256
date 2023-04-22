#include <iostream>
#include <chrono>
#include <ctime>
#include "SHA256.h"

int main() {

    std::string str;
    std::cout << "请输入需要加密的信息" << std::endl;
    std::cin >> str;
    SHA256 sha256;
    sha256.update(str);
    uint8_t * digest = sha256.digest();

    std::cout << sha256.toString(digest) << std::endl;


    delete[] digest;

    return 0;
}
