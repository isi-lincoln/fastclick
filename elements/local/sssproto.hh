#ifndef SSSPROTO_HH
#define SSSPROTO_HH

#define SSS_CLASSIFY_ANNO_OFFSET 4

#define SSSPROTO_DATA_LEN 8000 // max length

#define SSSPROTO_LEN_A 1 << 0
#define SSSPROTO_LEN_B 1 << 1


/*
 * SSSProto will encapsulate an IP packet 
 *
 *
 *
*/

struct SSSHeader {
#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
	unsigned int Len : 13; // packet length
	unsigned int Sharehost : 32; // packet is from (ipv4)
	unsigned int Shareid : 4; // number of share, max 15
	unsigned int Version : 3; // sss version
#elif CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
	unsigned int Version : 3;
	unsigned int Shareid : 4;
	unsigned int Sharehost : 32;
	unsigned int Len : 13;
#else
#error "Undefined Byte Order!"
#endif
}

struct SSSProto {
	SSSHeader Header;
	char Data[SSSPROTO_DATA_LEN];
} CLICK_SIZE_PACKED_ATTRIBUTE;

#endif
