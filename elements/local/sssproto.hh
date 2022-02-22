#ifndef SSSPROTO_HH
#define SSSPROTO_HH

// at another point lets do this dynamic and handle jumbos
#define SSSPROTO_DATA_LEN 1200 // max length

/*
 * SSSProto will encapsulate an IP packet 
*/

struct SSSProto {
#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
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
#else
#error "Undefined Byte Order!"
#endif
	char Data[SSSPROTO_DATA_LEN];
} CLICK_SIZE_PACKED_ATTRIBUTE;

#endif