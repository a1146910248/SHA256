#include "SHA256.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <cmath>

SHA256::SHA256() : m_blockLen(0),m_bitLen(0){
    m_state[0] = 0x6a09e667;
    m_state[1] = 0xbb67ae85;
    m_state[2] = 0x3c6ef372;
    m_state[3] = 0xa54ff53a;
    m_state[4] = 0x510e527f;
    m_state[5] = 0x9b05688c;
    m_state[6] = 0x1f83d9ab;
    m_state[7] = 0x5be0cd19;
}

//将字符串转换成转换为char数组，每个元素8bit进行分块处理
//str.c_str()将string类型转换成char数组
void SHA256::update(const std::string &str) {
    update(reinterpret_cast<const uint8_t *>(str.c_str()), str.size());
}

//将转换完的所有字符数组装进m_data中,每到64个即64x8=512个时进入transform块处理，
//并重制计数器m_blockLen，以便对所有整数的块（无需补充的块）进行处理。
//最后记录目前处理的字节长度m_bitLen += 512;
//对于最后不足512的块在pad进行处理
void SHA256::update(const uint8_t *data, size_t length) {
    for(int i = 0; i < length; i++) {
        m_data[m_blockLen++] = data[i];
        if(m_blockLen == 64){
            transform();

            m_blockLen = 0;
            m_bitLen += 512;
        }
    }
}


void SHA256::transform() {
    uint32_t w[64];
    uint32_t stat[8];

    //分成64组w[64]，其中前16组为消息本身二进制值顺序排列
    //对每个四个字节一组8*4=32bit，因为存入m_data数组的字节为固定8bit，故要进行扩充排列
    for(int i = 0, j = 0; i < 16; i++, j += 4) {
        w[i] = (m_data[j] << 24) | (m_data[j+1] << 16) | (m_data[j+2] << 8) | m_data[j+3];
    }

    //公式：w[i] = w[i - 16] + w[i - 7] + sig0(w[i - 15]) + sig1(w[i -2])
    //sig0 = (x rightrotate 7) xor (x rightrotate 18) xor (x rightshift 3)
    //sig 1 = (x rightrotate 17) xor (x rightrotate 19) xor (x rightshift 10)
    //其中rightrotate为循环右移，rightshift为右移高位补0
    for(int i = 16; i < 64; i++) {
        w[i] = w[i - 16] + w[i - 7] + sig0(w[i - 15]) + sig1(w[i -2]);
    }

    for(int i = 0; i < 8; i++){
        stat[i] = m_state[i];
    }

    //temp1,temp2为公式
    //Temp1 = h + Σ1 + Choice + k0 + w0
    //Temp2 = Σ0 + Majority
    for(int i = 0; i < 64; i++) {
        uint32_t temp1 = stat[7] + sigma1(stat[4]) +
                         choose(stat[4], stat[5], stat[6]) +
                         K[i] + w[i];
        uint32_t temp2 = sigma0(stat[0]) + majority(stat[0], stat[1], stat[2]);


        stat[7] = stat[6];
        stat[6] = stat[5];
        stat[5] = stat[4];
        stat[4] = stat[3] + temp1;
        stat[3] = stat[2];
        stat[2] = stat[1];
        stat[1] = stat[0];
        stat[0] = temp1 + temp2;
    }

    //最后得出的m_stat需要与计算的stat相加
    for(int i = 0; i < 8; i++) {
        m_state[i] += stat[i];
    }
}

/**
 *
 * @param x 原始值
 * @param n 右移位数
 * @return  循环右移结果
 * 先对其取移动位数的余例如 1101110 当n = 3时， temp = 110
 * 再将其右移再位与放大后的temp
 */
uint32_t SHA256::rotr(uint32_t x, uint32_t n) {
    uint32_t result;
    uint32_t temp = x % static_cast<uint32_t>(pow(2, n));
    x = x >> n;
    result = x | temp << (32 - n);
    return  result;
}

//Choice = (e and f) xor ((not e) and g)
uint32_t SHA256::choose(uint32_t e, uint32_t f, uint32_t g) {
    return (e & f) ^ ((~e) & g);
}

//Majority = (a and b) xor (a and c) xor (b and c)
uint32_t SHA256::majority(uint32_t a, uint32_t b, uint32_t c) {
    return (a & b) ^ (a & c) ^ (b & c);
}


//sig0 = (x rightrotate 7) xor (x rightrotate 18) xor (x rightshift 3)
uint32_t SHA256::sig0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}


/*sig 1 = (x rightrotate 17) xor (x rightrotate 19) xor (x rightshift 10)*/
uint32_t SHA256::sig1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

//(a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
uint32_t SHA256::sigma0(uint32_t a) {
    return rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
}

//(e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
uint32_t SHA256::sigma1(uint32_t e) {
    return rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
}

void SHA256::pad() {
    //记录处理完整数块后，最后一块的字节数
    //若其小于56，即不用多加块，否则需要补1和0到512bit再加一个512bit的块
    uint64_t i = m_blockLen;
    uint8_t end = (m_blockLen < 56 ? 56 : 64 );

    m_data[i++] = 0x80; //补1

    //补0到其为512bit的块
    while(i < end) {
        m_data[i ++] = 0x00;
    }

    //若需要再加块，则先处理补齐的块，再把新块的前56字节补0，留出64bit存放整个消息的字长
    if(m_blockLen >= 56) {
        transform();
        memset(m_data, 0, 56);
    }

    m_bitLen += (m_blockLen * 8);
    m_data[63] = m_bitLen;
    m_data[62] = m_bitLen >> 8;
    m_data[61] = m_bitLen >> 16;
    m_data[60] = m_bitLen >> 24;
    m_data[59] = m_bitLen >> 32;
    m_data[58] = m_bitLen >> 40;
    m_data[57] = m_bitLen >> 48;
    m_data[56] = m_bitLen >> 56;
    transform();
}

//SHA使用大端的字节序列
//一个m_state元素为32bit，一个十六进制数为4个bit，所以一个m_state可由8个十六进制数表示
//外层循环对应遍历处理8个m_state，内层循环将每个m_state分割四份分别处理成2个十六进制数
//处理方法是右移其自身所在32位数的位置使其靠最右八位并只保留低八位
void SHA256::revert(uint8_t * hash) {
    for(int i = 0; i < 8; i++) {
        for(int j = 0; j < 4; j++) {
            hash[j + i * 4] = (m_state[i] >> (24 - j * 8)) & 0x000000ff;
        }
    }
}

//摘要,化16进制
uint8_t *SHA256::digest() {
    uint8_t * hash = new uint8_t [32];
    pad();
    //化16进制
    revert(hash);
    return hash;
}

std::string SHA256::toString(const uint8_t *digest) {
    std::stringstream s;
    s << std::setfill('0') << std::hex;

    for(uint8_t i = 0; i < 32; i++){
        s << std::setw(2) << (unsigned int) digest[i];
    }

    return s.str();
}