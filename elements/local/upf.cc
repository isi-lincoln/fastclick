#include <string>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <click/config.h>
#include "upf.hh"
#include <click/packet_anno.hh>
#include <click/args.hh>
#include <click/error.hh>
#include <clicknet/ip.h> // ip header checksum
#include <clicknet/icmp.h> // icmp header checksum
#include <clicknet/tcp.h> // tcp header checksum
#include <clicknet/udp.h> // udp header checksum
#include <clicknet/ether.h>
#include <include/click/packet.hh> // pkt make
#include <click/string.hh>
CLICK_DECLS


UPF::UPF()
{
}

int
UPF::configure(Vector<String>& conf, ErrorHandler* errh)
{
    _encode = false;
    _maxlength = 0;
    _verbose = false;

    return Args(conf, this, errh)
        .read_p("ENCODE", _encode)
        .read_p("SA", _sa)
        .read_p("DA", _da)
        .read("PREFIX", _prefix)
        .read("MAXLENGTH", _maxlength)
        .read("VERBOSE", _verbose)
        .complete();

    return 0;
}

Packet*
UPF::simple_action(Packet* p)
{
    Packet* tc = p->clone();
    WritablePacket* t = tc->put(0);
    WritablePacket* q;
    std::string buf = "USC/ISI-UPF";
    printf("encoding: %d\n", _encode);


    if (_encode) {
        q = p->put(buf.length());
        memcpy((void*)(q->end_data()-buf.length()), (void*)buf.c_str(), buf.length());

        if (p->has_mac_header()) {
            const click_ether *mch = (click_ether *) p->data();
            const unsigned char *mh = p->mac_header();

            if (htons(mch->ether_type) != ETHERTYPE_IP) {
                fprintf(stderr, "handling non-ipv4 packet: %x\n", htons(mch->ether_type));
                return p;
            }

            if (!p->has_network_header()) {
                fprintf(stderr, "dont know how to handle this packet (no L3).\n");
                return p;
            }

            printf("in encode: doing work\n");

            //const click_ip *iph = q->ip_header();
            click_ip *iph = q->ip_header();
            //click_ip *iph = (click_ip *)q->data();
            //std::cout << "src: " << IPAddress(iph->ip_src).unparse().c_str() << "\n";
            //std::cout << "dst: " << IPAddress(iph->ip_dst).unparse().c_str() << "\n";
            if (iph->ip_dst != IPAddress(_da)) {
                return p;
            }
            //std::cout << "new src: " << IPAddress(_sa).unparse().c_str() << "\n";
            //std::cout << "new dst: " << IPAddress(_da).unparse().c_str() << "\n";

            //printf("size change %d -> %ld\n", ntohs(iph->ip_len), ntohs(iph->ip_len)+buf.length());
            iph->ip_len = htons(ntohs(iph->ip_len)+buf.length());
            printf("new length %d\n", ntohs(iph->ip_len));

	    dlock.acquire();
	    std::ofstream myfile;
            myfile.open("ip.txt");
            myfile << IPAddress(iph->ip_src).unparse().c_str();
            myfile.close();
	    dlock.release();

            iph->ip_sum = 0;
            iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));

            printf("proto: %d\n", iph->ip_p);
            if (iph->ip_p == IP_PROTO_ICMP) {

                unsigned hlen = iph->ip_hl << 2;
                unsigned ilen = ntohs(iph->ip_len);
                click_icmp *icmph = (click_icmp *) (((char *)iph) + hlen);

                icmph->icmp_cksum = 0;
                // so this should be correct - 29 bytes, 10 for data, 11 for mine, 8 for icmp header
                icmph->icmp_cksum = click_in_cksum((unsigned char *)icmph, ilen - hlen);
            } else if (iph->ip_p == IP_PROTO_TCP) {

                    click_ip *tiph = t->ip_header();
                    click_tcp *ttcph = (click_tcp*) t->tcp_header();

                    unsigned plen = ntohs(tiph->ip_len) - (tiph->ip_hl << 2);
                    unsigned csum;

                    if (!t->has_transport_header() || plen < sizeof(click_tcp) || plen > (unsigned)t->transport_length()){
		        return t;
		    }


		    dlock.acquire();
		    std::ofstream myfile2;
		    myfile2.open("tcp.txt");
		    myfile2 << ntohs(ttcph->th_sport);
		    myfile2.close();
		    dlock.release();

		    ttcph->th_sport = htons(11000);

                    unsigned off = ttcph->th_off << 2;
                    if (off < sizeof(click_tcp)) {
                        ttcph->th_off = sizeof(click_tcp) >> 2;
		    }
                    else if (off > plen && !IP_ISFRAG(tiph)) {
                        ttcph->th_off = plen >> 2;
		    }

                    ttcph->th_sum = 0;
                    csum = click_in_cksum((unsigned char *)ttcph, plen);
                    ttcph->th_sum = click_in_cksum_pseudohdr(csum, tiph, plen);

		    p->kill();
		    return t;
            } else if (iph->ip_p == IP_PROTO_UDP) {

            }

        }
    // decode
    } else {
        if (p->has_mac_header()) {
            const click_ether *mch = (click_ether *) p->data();
            const unsigned char *mh = p->mac_header();

            if (htons(mch->ether_type) != ETHERTYPE_IP) {
                fprintf(stderr, "handling non-ipv4 packet: %x\n", htons(mch->ether_type));
                return p;
            }

            if (!p->has_network_header()) {
                fprintf(stderr, "dont know how to handle this packet (no L3).\n");
                return p;
            }

            printf("in decode: doing work\n");

            char tmp[buf.length()];
            memcpy((void*)tmp, (void*)(p->end_data()-buf.length()), buf.length());
            std::string tmp_str(tmp);

            printf("last bytes: %s ~~~ %s\n", tmp_str.c_str(), buf.c_str());

            int key = strncmp(tmp_str.c_str(),buf.c_str(), buf.length());
            if (key == 0) {
                printf("one of ours\n");

                q = p->push(0);
                click_ip *iph = q->ip_header();
                if (iph->ip_dst != IPAddress(_da)) {
		    printf("not correct: %s ~~ %s\n", IPAddress(iph->ip_dst).unparse().c_str(), IPAddress(_da).unparse().c_str());
                    return p;
                }

                q->take(buf.length());

                printf("size change %d -> %ld\n", ntohs(iph->ip_len), ntohs(iph->ip_len)-buf.length());
                iph->ip_len = htons(ntohs(iph->ip_len)-buf.length());


		printf("prefix: %s\n", IPAddress(_prefix).unparse().c_str());

                std::string line;
		std::string addr;
	        dlock.acquire();
		std::ifstream myfile;
                myfile.open("ip.txt");
                while ( getline (myfile,line) ) {
                  addr = line;
		}
                myfile.close();
	        dlock.release();

		//iph->ip_dst = IPAddress(tmpAddr);
		iph->ip_dst = IPAddress(String(addr.c_str()));

                iph->ip_sum = 0;
                iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));

                printf("proto: %d\n", iph->ip_p);
                if (iph->ip_p == IP_PROTO_ICMP) {
                    unsigned hlen = iph->ip_hl << 2;
                    unsigned ilen = ntohs(iph->ip_len);
                    printf("data in icmp2: %d\n", ilen - hlen);
                    click_icmp *icmph = (click_icmp *) (((char *)iph) + hlen);
                    printf("before checksum: %x\n", icmph->icmp_cksum);

                    icmph->icmp_cksum = 0;
                    icmph->icmp_cksum = click_in_cksum((unsigned char *)icmph, ilen - hlen);
                    printf("after checksum: %x\n", icmph->icmp_cksum);
                } else if (iph->ip_p == IP_PROTO_TCP) {
                    click_ip *tiph = (click_ip*) t->ip_header();
                    click_tcp *tcph = (click_tcp*) t->tcp_header();
                    unsigned plen = ntohs(tiph->ip_len) - (tiph->ip_hl << 2);
                    unsigned csum;

                    if (!t->has_transport_header() || plen < sizeof(click_tcp) || plen > (unsigned)t->transport_length()){
		        return t;
		    }

                std::string line2;
		std::string addr2;
	        dlock.acquire();
		std::ifstream myfile2;
                myfile2.open("tcp.txt");
                while ( getline (myfile2,line2) ) {
                  addr2 = line2;
		}
                myfile.close();
	        dlock.release();
		unsigned short port = atol(addr2.c_str());
                printf("address change %s: %d->%d\n", addr.c_str(), ntohs(tcph->th_dport), port);
		tcph->th_dport = htons(port);

                    unsigned off = tcph->th_off << 2;
                    if (off < sizeof(click_tcp)) {
                        tcph->th_off = sizeof(click_tcp) >> 2;
		    }
                    else if (off > plen && !IP_ISFRAG(iph)) {
                        tcph->th_off = plen >> 2;
		    }

                    tcph->th_sum = 0;
                    csum = click_in_cksum((unsigned char *)tcph, plen);
                    tcph->th_sum = click_in_cksum_pseudohdr(csum, tiph, plen);
		    p->kill();
		    return t;
                } else if (iph->ip_p == IP_PROTO_UDP) {

                }


            } else {
                printf("not one a modified one. editing dst ip\n");

                click_ip *iph = t->ip_header();

                std::string line;
		std::string addr;
	        dlock.acquire();
		std::ifstream myfile;
                myfile.open("ip.txt");
                while ( getline (myfile,line) ) {
                  addr = line;
		}
                myfile.close();
	        dlock.release();

		iph->ip_dst = IPAddress(String(addr.c_str()));

                iph->ip_sum = 0;
                iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));

                if (iph->ip_p == IP_PROTO_TCP) {
                    click_ip *tiph = (click_ip*) t->ip_header();
                    click_tcp *tcph = (click_tcp*) t->tcp_header();
                    unsigned plen = ntohs(tiph->ip_len) - (tiph->ip_hl << 2);
                    unsigned csum;

                    if (!t->has_transport_header() || plen < sizeof(click_tcp) || plen > (unsigned)t->transport_length()){
		        return t;
		    }


                std::string line2;
		std::string addr2;
	        dlock.acquire();
		std::ifstream myfile2;
                myfile2.open("tcp.txt");
                while ( getline (myfile2,line2) ) {
                  addr2 = line2;
		}
                myfile.close();
	        dlock.release();
		unsigned short port = atol(addr2.c_str());
                printf("address change %s: %d->%d\n", addr.c_str(), ntohs(tcph->th_dport), port);
		tcph->th_dport = htons(port);

                    unsigned off = tcph->th_off << 2;
                    if (off < sizeof(click_tcp)) {
                        tcph->th_off = sizeof(click_tcp) >> 2;
		    }
                    else if (off > plen && !IP_ISFRAG(iph)) {
                        tcph->th_off = plen >> 2;
		    }

                    tcph->th_sum = 0;
                    csum = click_in_cksum((unsigned char *)tcph, plen);
                    tcph->th_sum = click_in_cksum_pseudohdr(csum, tiph, plen);
		    printf("tcp flags: RST: %d, SYN: %d, ACK: %d, FIN: %d, PSH: %d, URG: %d, ECE: %d, CWR: %d, NS: %d\n",
			tcph->th_flags & TH_RST,
			tcph->th_flags & TH_SYN,
			tcph->th_flags & TH_ACK,
			tcph->th_flags & TH_FIN,
			tcph->th_flags & TH_PUSH,
			tcph->th_flags & TH_URG,
			tcph->th_flags & TH_ECE,
			tcph->th_flags & TH_CWR,
			tcph->th_flags & TH_NS);

		    if (tcph->th_flags & TH_RST) {
			printf("packet killed\n");
		    	p->kill();
			return NULL;
		    }
		}

                printf("finished edit\n");
		p->kill();
		return t;
            }

        } else {
            printf("missing mac. sending\n");
            return p;
        }

    }

    p = q;

    SET_EXTRA_LENGTH_ANNO(p, 0);
    return p;
}

CLICK_ENDDECLS

EXPORT_ELEMENT(UPF)
ELEMENT_MT_SAFE(UPF)
