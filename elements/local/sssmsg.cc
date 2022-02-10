#include <click/config.h>
#include "sssmsg.hh"
#include "sssproto.hh"


/*****   THIS IS THE CRYPTO SECTION *****/
#include <iostream>
#include <cstdlib>
#include <sstream> // istream

#include <cryptopp/ida.h> // SecretSharing
#include <cryptopp/osrng.h> // RandomNumberGenerator
#include <cryptopp/randpool.h> // RandomPool
#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>  // SecBlock
#include <cryptopp/files.h> // FileSource
 
using namespace std;
using namespace CryptoPP;

std::vector<std::string> SecretShareData(int threshold, int nShares, std::string secret) {
	// rng
	CryptoPP::AutoSeededRandomPool rng;
	
	// modify our string into cryptopp vector
	std::vector<CryptoPP::byte> secVec(secret.begin(), secret.end());
	std::vector<CryptoPP::byte> shareVec(nShares);

	// initialize channelswitch (moves data from source to sink through filters)
	CryptoPP::ChannelSwitch *channelSwitch;

	// typedef of StringSource( byte *string, size_t length, pumpall, BufferedTransformation)
	// create a source that uses our secret, and puts a filter (secret sharing) to move the
	// data using our channel switch above
	CryptoPP::VectorSource source(secVec, false, new CryptoPP::SecretSharing(
			rng,
			threshold,
			nShares,
			channelSwitch = new CryptoPP::ChannelSwitch
		)
	);


	// from ida example, just use string instead of vector
	std::vector<std::string> strShares(nShares);
	vector_member_ptrs<StringSink> strSinks(nShares);

	std::string channel;

	// based on the number of shares to generate, we know go through and do the computation
	for (int i = 0; i < nShares; i++)	{
		// creates a new StringSink set to shares[i]
		strSinks[i].reset(new StringSink(strShares[i]));

		channel = CryptoPP::WordToString<word32>(i);
        	strSinks[i]->Put( (CryptoPP::byte *)channel.data(), 4 ); // 4 because 32/8 is 4
 		channelSwitch->AddRoute( channel,*strSinks[i], DEFAULT_CHANNEL );
	}

	source.PumpAll();

	return strShares;
}

std::string SecretRecoverData(int threshold, std::vector<std::string> shares) {
	std::string secret;
	CryptoPP::SecretRecovery recovery(threshold, new StringSink(secret));

	vector_member_ptrs<StringSource> strSources(threshold);

	CryptoPP::SecByteBlock channel(4);
	int i;
	for (i=0; i<threshold; i++)
	{
		strSources[i].reset(new StringSource(shares[i], false));
		strSources[i]->Pump(4);
		strSources[i]->Get(channel, 4);
		strSources[i]->Attach(new CryptoPP::ChannelSwitch(recovery, std::string((char *)channel.begin(), 4)));
	}

	while (strSources[0]->Pump(256))
		for (i=1; i<threshold; i++)
			strSources[i]->Pump(256);

	for (i=0; i<threshold; i++)
		strSources[i]->PumpAll();

	return secret;
}
/*****   THIS IS END CRYPTO SECTION *****/


CLICK_DECLS

SSSMsg::SSSMsg() { };
SSSMsg::~SSSMsg() { };

/*
 * Generates a SSSMsg packet from a packet.
 * 
 * Requires that the packet is IP, and has been checked.
 */
Packet *SSSMsg::gen_pkt(Packet *p, uint8_t shares, uint8_t threshold) {

	// TODO: packet length bounds check.
	if p->length() > 8000 {
		// too large
	}
	// TODO: shares bound check
	if shares > 15 || shares < 2 {
		// too few/many shares
	}

	struct SSSProto ssspkt;

	// this packet is actually an ip packet wink wink.
	// want this in order to get the ip address.
    	const click_ip *ip = reinterpret_cast<const click_ip *>(p->data());

	// packet is the size of ip packet + size of our SSSHeader
	ssspkt.Len = p->length()+sizeof(SSSHeader);

	// source ip address is the share host (originator of data)
	// TODO: validate ip address
	ssspkt.Sharehost = ip->ip_src.data();
	
	// initial version of protocol
	ssspkt.Version = 0; 


	// convert our ip packet from data into a string
	std::string pkt_data;
	int rc = snprintf(pkt_data, p->length(), "%s", p->data());

	// do the hard work to convert data to encoded forms
	std::vector<std::string> encoded = SecretShareData(threshold, shares, pkt_data);
	
	// now lets create the shares
	SSSProto pkt_shares[shares];
	Packet *pkts[shares];
	for (int i = 0; i < shares; ++i) {
		ssspkt.Shareid = i;

		// encoded has the same length as the original data
		ssspkt.Data = encoded[i];

        	memcpy(pkt_shares[i], ssspkt, ssspkt.Len);
		pkts[i] = Packet::make(headroom, pkt_shares[i], sizeof(SSSProto), 0);
	}

	return pkts;
};

Packet *SSSMsg::simple_action(Packet *p) {
	Packet *q = NULL;
	int len = strnlen((const char *) p->data(), p->length());

	if (len > SSSPROTO_DATA_LEN)
		len = SSSPROTO_DATA_LEN;
	
	String s = String(p->data(), len);
	int delta = SSSPROTO_DATA_LEN - len;

	if (delta > 0)
		s.append_fill('\0', delta);

	click_chatter("DEBUG: p->data() = %s\tp->length() = %d", s.c_str(), p->length());

	if (p->length() > 0 && p->length() <= SSSPROTO_DATA_LEN + 1)
		q = gen_dummy_request(s);
	else
		click_chatter("ERROR: Input packet is too big or 0-sized!");

	p->kill();

	return q;
};

CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(SSSMsg)
