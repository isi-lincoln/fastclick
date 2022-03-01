// address info for each of the interfaces

// config file for device b
AddressInfo(
	eth1-dev	192.168.0.101	192.168.0.0/24	04:70:00:00:00:02,
	eth2-dev	10.0.0.2	10.0.0.0/24	04:70:00:00:00:11,
	eth3-dev	10.0.1.2	10.0.1.0/24	04:70:00:00:00:21,
	eth4-dev	10.0.2.2	10.0.2.0/24	04:70:00:00:00:31,

	eth1-neigh	192.168.0.2	192.168.0.0/24	04:70:00:00:02:01,
	eth2-neigh	10.0.0.1	10.0.0.0/24	04:70:00:00:00:10,
	eth3-neigh	10.0.1.1	10.0.1.0/24	04:70:00:00:00:20,
	eth4-neigh	10.0.2.1	10.0.2.0/24	04:70:00:00:00:30,
);

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
	dst host 192.168.0.1
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

encrypt	:: SSSMsg(3,2,0);
decrypt	:: SSSMsg(3,2,1);


/* handle the arp requests */

data_in		->	classifier0[0]	->	Print("a")	->	ARPResponder(192.168.0.1 192.168.0.0/24 04:70:00:00:01:01)	->	q1;

left_in_device	->	classifier1[0]	->	Print("b")	->	ARPResponder(10.0.0.1 10.0.0.0/24 04:70:00:00:00:10)	->	q2;
center_in_device ->	classifier2[0]	->	Print("c")	->	ARPResponder(10.0.1.1 10.0.1.0/24 04:70:00:00:00:20)	->	q3;
right_in_device ->	classifier3[0]	->	Print("d")	->	ARPResponder(10.0.2.1 10.0.2.0/24 04:70:00:00:00:30)	->	q4;


// if this is an ip packet
// and it is dest host y -> rewrite the eth header now
// then send it to SSS, 3 shares, 2 threshold, and set option to encrypt
classifier0[1]	->	Print("e")	->	chip	->	ipclassifier[0]	->	IPPrint("ip pkt")	->	EtherRewrite(04:70:00:00:00:01, 04:70:00:00:01:01)	->	encrypt;

// then these will be the encoded chunks
encrypt[0]	->	q2;
encrypt[1]	->	q3;
encrypt[2]	->	q4;


// if the packet is coming over one of or other links, it means its already encrypted and ready to be decrypted.
classifier1[1]	->	decrypt;
classifier2[1]	->	decrypt;
classifier3[1]	->	decrypt;


decrypt	->	q1;

// now send out everything from our queues
q1	->	data_out;
q2	->	left_out_device;
q3	->	center_out_device;
q4	->	right_out_device;
