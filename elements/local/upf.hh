// -*- c-basic-offset: 4 -*-
#ifndef CLICK_UPF_HH
#define CLICK_UPF_HH
#include <click/batchelement.hh>
CLICK_DECLS

/*
=c

UPF([LENGTH, I<keyword> ZERO])

=s basicmod

extend packet length

=d

Extend packets to at least LENGTH bytes.

If LENGTH is omitted, then input packets are extended to the length
indicated by their extra length annotations. Output packets always have
extra length annotation zero.

Keyword arguments are:

=over 8

=item ZERO

Boolean. If true, then set added packet data to zero; if false, then
additional packet data is left uninitialized (which might be a security
problem). Default is true.

=item USC

Boolean. If true, Adds "USC/ISI-UPF". Exclusive with ZERO. Default is false.

=item MAXLENGTH

Int. If >0, it specifies the maximum length that a packet can have after upfding.
If the final length would be higher than this, the packet will be truncated to MAXLENGTH

=back

=a Truncate
*/

class UPF : public SimpleElement<UPF> { public:

    UPF() CLICK_COLD;

    const char *class_name() const override		{ return "UPF"; }
    const char *port_count() const override		{ return PORTS_1_1; }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    bool can_live_reconfigure() const		{ return true; }

    Packet *simple_action(Packet *);

  private:

    unsigned _nbytes;
    unsigned _maxlength;
    bool _verbose;
};

CLICK_ENDDECLS
#endif
