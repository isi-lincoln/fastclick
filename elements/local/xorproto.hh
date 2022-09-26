#ifndef XORPROTO_HH
#define XORPROTO_HH

// at another point lets do this dynamic and handle jumbos
#define XORPROTO_DATA_LEN 8000 // max length

/*
 * XORProto will XOR two ip packets together to obfuscate
 * the data being carried.  Theoretically, it could be
 * any number of packets, but for simpliestity and not
 * requiring defenses about attackers injecting flows
 * we will just focus one 2 packets.
*/

#define DEFAULT_MAC_LEN 14

// our header is 128+16 bits = 18 bytes
// then 14 for mac
// and 20 for ip
// 34+18 = 52 byte total used by our header
#define XORPKT_HEADER_LEN 52

// To avoid polution attack, these need to be signed to ensure attacker
// cant DOS the data by providing known symbols to destination to prevent
// code from being decoded.
struct XORProto {
#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
	unsigned int Version : 3; // xor version
	unsigned int Len : 13; // packet length log_2(8000)
	unsigned long long SymbolA: 48; // unique packet identifer for A
	unsigned long long SymbolB: 48;  // unique packet identifer for B
	unsigned long long SymbolC: 48;  // unique packet identifer for C
	unsigned long long Timer: 64;
#elif CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
	unsigned long long Timer: 64;
	unsigned long long SymbolC: 48;  // unique packet identifer for B
	unsigned long long SymbolB: 48;  // unique packet identifer for B
	unsigned long long SymbolA: 48; // unique packet identifer for A
	unsigned int Len : 13; // packet length log_2(8000)
	unsigned int Version : 3; // xor version
#else
#error "Undefined Byte Order!"
#endif
	char Data[XORPROTO_DATA_LEN];
} CLICK_SIZE_PACKED_ATTRIBUTE;

#endif
