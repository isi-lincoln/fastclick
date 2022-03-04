#ifndef SSSPROTO_HH
#define SSSPROTO_HH

// at another point lets do this dynamic and handle jumbos
#define SSSPROTO_DATA_LEN 1200 // max length

/*
 * SSSProto will encapsulate an IP packet 
*/

// 13+32+32+4+3 = 84 / 8 = 11 bytes
#define SSSPROTO_NONDATA_LEN 11

#define DEFAULT_MAC_LEN 14

#define SSSMAGIC 0x0a1b

struct SSSProto {
#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
        unsigned char Magic: 8; // for classifier
	unsigned int Len : 13; // packet length
	unsigned long Sharehost : 32; // packet is from (ipv4)
	unsigned long Flowid : 32;
	unsigned int Shareid : 4; // number of share, max 15
	unsigned int Version : 3; // sss version
#elif CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
	unsigned int Version : 3;
	unsigned int Shareid : 4;
	unsigned long Flowid : 32;
	unsigned long Sharehost : 32;
	unsigned int Len : 13;
	unsigned char Magic: 8;
#else
#error "Undefined Byte Order!"
#endif
	char Data[SSSPROTO_DATA_LEN];
} CLICK_SIZE_PACKED_ATTRIBUTE;

#endif
