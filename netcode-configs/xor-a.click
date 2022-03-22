classifier0	:: Classifier(
	12/0806 20/0001, /* arp requests */
	-,
	);

classifier1	:: Classifier(
	12/0806 20/0001, /* arp requests */
	-,
	);

classifier2	:: Classifier(
	12/0806 20/0001, /* arp requests */
	-,
	);

classifier3	:: Classifier(
	12/0806 20/0001, /* arp requests */
	-,
	);

ipclassifier	:: IPClassifier(
	dst host 192.168.2.2
	);

data_in			::	FromDevice(eth1);
left_in_device		::	FromDevice(eth2);
center_in_device	::	FromDevice(eth3);
right_in_device		::	FromDevice(eth4);

data_out		::	ToDevice(eth1);
left_out_device		::	ToDevice(eth2);
center_out_device	::	ToDevice(eth3);
right_out_device	::	ToDevice(eth4);

q1	:: ThreadSafeQueue(200);
q2	:: ThreadSafeQueue(200);
q3	:: ThreadSafeQueue(200);
q4	:: ThreadSafeQueue(200);

chip	:: MarkIPHeader(14);
chip1	:: MarkIPHeader(14);
chip2	:: MarkIPHeader(14);
chip3	:: MarkIPHeader(14);
chip4	:: MarkIPHeader(14);

encode	:: XORMsg(3,0);
decode	:: XORMsg(3,1);


/* handle the arp requests */

data_in		->	classifier0[0]	->	Print("a")	->	ARPResponder(192.168.2.2 192.168.2.0/24 04:70:00:00:00:01)	->	q1;

left_in_device	->	classifier1[0]	->	Print("b")	->	ARPResponder(10.0.0.1 10.0.0.0/24 04:70:00:00:00:10)	->	q2;
center_in_device ->	classifier2[0]	->	Print("c")	->	ARPResponder(10.0.1.1 10.0.1.0/24 04:70:00:00:00:20)	->	q3;
right_in_device ->	classifier3[0]	->	Print("d")	->	ARPResponder(10.0.2.1 10.0.2.0/24 04:70:00:00:00:30)	->	q4;


// if this is an ip packet
// and it is dest host y -> rewrite the eth header now
// then send it to SSS, 3 shares, 2 threshold, and set option to encode
classifier0[1]	->	Print("e")	->	chip	->	ipclassifier[0]	->	encode;

// then these will be the encoded chunks
encode[0]	->	EtherRewrite(04:70:00:00:00:10, 04:70:00:00:03:10)	->	q2;
encode[1]	->	EtherRewrite(04:70:00:00:00:20, 04:70:00:00:03:20)	->	q3;
encode[2]	->	EtherRewrite(04:70:00:00:00:30, 04:70:00:00:03:30)	->	q4;


// if the packet is coming over one of or other links, it means its already encodeed and ready to be decodeed.
classifier1[1]	->	EtherRewrite(04:70:00:00:03:11, 04:70:00:00:00:11)      ->	chip1	->	decode;
classifier2[1]	->	EtherRewrite(04:70:00:00:03:21, 04:70:00:00:00:21)      ->	chip2	->	decode;
classifier3[1]	->	EtherRewrite(04:70:00:00:03:31, 04:70:00:00:00:31)      ->	chip3	->	decode;

decode	->	chip4	->	IPPrint("after")	->	EtherRewrite(04:70:00:00:00:01, 04:70:00:00:01:01)	->	q1;

// now send out everything from our queues
q1	->	data_out;
q2	->	left_out_device;
q3	->	center_out_device;
q4	->	right_out_device;
