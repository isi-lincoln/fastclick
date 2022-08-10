/*

#ifndef CLICK_SSSCLASSIFIER__HH
#define CLICK_SSSCLASSIFIER__HH

#include <click/element.hh>

CLICK_DECLS

/\*
=c

SSSClassifier()

=s

Classify according to the type of an sss packet, using MAGIC set in header.

=d

SSSProto packets go out first output port, everything else goes out second.
*\/
class SSSClassifier : public Element {

	public:
		SSSClassifier();
		~SSSClassifier();

		const char *class_name() const { return "SSSClassifier"; }
		const char *port_count() const { return "1/2"; }
		const char *processing() const { return PUSH; }

		void push(int, Packet *p);
};

CLICK_ENDDECLS

#endif

*/
