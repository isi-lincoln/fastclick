#include <string>
#include <stdio.h>
#include <iostream>
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

            printf("proto: %d\n", iph->ip_p);
            if (iph->ip_p == IP_PROTO_ICMP) {

                unsigned hlen = iph->ip_hl << 2;
                unsigned ilen = ntohs(iph->ip_len);
                click_icmp *icmph = (click_icmp *) (((char *)iph) + hlen);

                icmph->icmp_cksum = 0;
                // so this should be correct - 29 bytes, 10 for data, 11 for mine, 8 for icmp header
                icmph->icmp_cksum = click_in_cksum((unsigned char *)icmph, ilen - hlen);
            } else if (iph->ip_p == IP_PROTO_TCP) {

            } else if (iph->ip_p == IP_PROTO_UDP) {

            }

            iph->ip_sum = 0;
            iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));
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

                } else if (iph->ip_p == IP_PROTO_UDP) {

                }
                printf("proto: %d\n", iph->ip_p);

                iph->ip_sum = 0;
                iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));

                printf("prefix: %s\n", IPAddress(_prefix).unparse().c_str());

                if (IPAddress(_prefix) != IPAddress("0.0.0.0")) {
                        printf("not empty\n");
                        for (int i = 4; i < 254; i++) { // 4 to 254
                                //WritablePacket* tpkt = q->uniqueify();
                                WritablePacket* tpkt = Packet::make(q->data(), q->length());
                                tpkt = q;
                                click_ip *tiph = tpkt->ip_header();
                                char tmp[100];
                                sprintf(tmp, "0.0.0.%d", i);
                                IPAddress x = IPAddress(tmp);
                                IPAddress update = IPAddress(_prefix) | IPAddress(x);
                                tiph->ip_dst = IPAddress(update);
                                tiph->ip_sum = 0;
                                tiph->ip_sum = click_in_cksum((unsigned char *)tiph, sizeof(click_ip));
                                output(0).push(tpkt->clone());
                                printf("sent packet to %s\n", IPAddress(update).unparse().c_str());
                        }
                }

            } else {
                return p;
            }

        } else {
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
