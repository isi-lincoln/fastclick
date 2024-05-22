// -*- c-basic-offset: 4 -*-
#ifndef CLICK_UPF_HH
#define CLICK_UPF_HH
#include <click/batchelement.hh>
#include <clicknet/ip.h> // ip header 
CLICK_DECLS

class UPF : public SimpleElement<UPF> { public:

    UPF() CLICK_COLD;

    const char *class_name() const override             { return "UPF"; }
    const char *port_count() const override             { return PORTS_1_1; }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    bool can_live_reconfigure() const           { return true; }

    Packet *simple_action(Packet *);

  private:

    bool _encode;
    unsigned _maxlength;
    bool _verbose;
    struct in_addr _sa;
    struct in_addr _da;
    struct in_addr _prefix;
};

CLICK_ENDDECLS
#endif
