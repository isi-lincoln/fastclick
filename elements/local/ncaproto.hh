#ifndef NCAPROTO_HH
#define NCAPROTO_HH

// at another point lets do this dynamic and handle jumbos
#define NCAPROTO_DATA_LEN 8000 // max length

/*
 * NCAProto will code together a set of ip together to obfuscate
 * the traffic being transmited.

 * This iteration will require full rank matrix in order to decode.
*/

#define DEFAULT_MAC_LEN 14

// To avoid polution attack, these need to be signed to ensure attacker
// cant DOS the data by providing known symbols to destination to prevent
// code from being decoded.
struct NCAProto {
#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
    unsigned int Version : 3; // xor version
    unsigned int Len : 13; // packet length log_2(8000)
    unsigned int Pkts : 8; // up to 256 packets together
    unsigned long long Id: 48; // identifier
    // with 3 packets, use 2 bits for row, and 8 bits per symbol
    unsigned long long Equation: 26; // 8 bits per pkt, current version is hard coded to 3 packets
    //unsigned int field: 8;
    //unsigned long long PP: 48 // Primative Polynomial
#elif CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
    unsigned long long Equation: 26; // 8 bits per pkt, current version is hard coded to 3 packets
    unsigned long long Id: 48; // identifier
    unsigned int Pkts : 8; // up to 256 packets together
    unsigned int Len : 13; // packet length log_2(8000)
    unsigned int Version : 3; // xor version
#else
#error "Undefined Byte Order!"
#endif
    char Data[NCAPROTO_DATA_LEN];
} CLICK_SIZE_PACKED_ATTRIBUTE;

#endif
