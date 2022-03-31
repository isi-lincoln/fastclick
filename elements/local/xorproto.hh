#ifndef XORPROTO_HH
#define XORPROTO_HH

// at another point lets do this dynamic and handle jumbos
#define XORPROTO_DATA_LEN 5000 // max length


/*
 * We have a security issue with xor.  Because we rely on X number of incoming packets
 * to xor to create some notion of security.  We run into an issue when we send our last packet.
 * because the last packet needs to be in the clear, but then an adversary can unwind the xor chain.

 * so a single link approach is out of the question.

 * If we do a windowing approach, where we send let us say 3 packets, xor'd into a single packet
 * We then need to send 2 windows of other XOR packets to get all three of the original XOR'd
 * packets.
 * as a graphic:
 * window 1: [ pkt1 ^ pkt2 ^ pkt3 ]
 * window 2: [ pkt2 ^ pkt3 ]
 * window 3: [ pkt1 ^ pkt3 ]
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

 * classic approach would be send:
 * link1: [pkt1 ^ pkt2]
 * link2: pkt2

 * this has the obvious security issue of having pkt2 be in the clear.

 * so window approach seems like the same issue as the classical, unless the number of packets
 * in the xor exchange is equal to the number of links.  Then we can keep each xor exchange
 * across a different link, and each link cannot compute any single packet.

 * Lets start with a 3 packet solution, such as the window one above, and enforce that the
 * minimum number of links is 3.  With more links, comes additional redundancy. 

 * So this approach without padding works as long as the packets are the same length, and once
 * they are different, data can be extracted.

 * So is it possible to support a single value to represent the difference of all three packet
 * lengths.  I dont think so, so we need 2 values to track the size differences.  Then we need to
 * PRNG the padded values for XOR.  It is then up to end host to chop off the padding to get the
 * original values after XOR.  So, how do we track the padded difference positionally?

 * We can set packet A to always be the longest, then B, then C.  If padding value is large enough
 * we can use high low bit masks, but that is the same as 2 separate values.  So is anything leaked
 * by an adversary knowing the packet lengths?

 * Can we also enforce in someway that an adversary cannot force retransmits that cause another
 * encoded value to be sent, allowing decryption?  e.g,
 * first round adv. gets pkt1^pkt2, drops, underlying app/tcp retransmits, second round gets 
 * pkt1^pkt2^pkt3, so now advesary knows pkt3 - so we would need to (in the future) enforce same
 * link retransmitions. 

 * security implications when we dont have a full window.
*/

struct XORProto {
#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
	unsigned long Len : 13; // sizeof(A)
	unsigned long Flowid: 16; // flow identifier
        unsigned int Pktid: 3; // pkt identifier, atmost 8
	unsigned int Order: 3; // pkt order in window
	unsigned long BPadd: 13; // sizeof(A)-sizeof(B)
	unsigned long CPadd: 13; // sizeof(A)-sizeof(C)
	unsigned int Version : 3; // protocol version
#elif CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
	unsigned int Version : 3;
	unsigned long CPadd: 13;
	unsigned long BPadd: 13;
	unsigned int Order: 3;
        unsigned int Pktid: 3;
	unsigned long Flowid: 16;
	unsigned long Len : 13;
#else
#error "Undefined Byte Order!"
#endif
	unsigned char Data[XORPROTO_DATA_LEN];
} CLICK_SIZE_PACKED_ATTRIBUTE;

#endif
