// address info for each of the interfaces
AddressInfo(
        eth1-dev        10.0.0.11       10.0.0.0/24     04:70:00:00:00:11,
        eth2-dev        10.0.1.12       10.0.1.0/24     04:70:00:00:00:12,

        eth1-neigh      10.0.0.1        10.0.0.0/24     04:70:00:00:00:01,
        eth2-neigh      10.0.1.2        10.0.1.0/24     04:70:00:00:00:02,
);

left_in_device          ::      FromDevice(eth1);
right_in_device          ::      FromDevice(eth2);

left_out_device         ::      ToDevice(eth1);
right_out_device         ::      ToDevice(eth2);

q1              :: ThreadSafeQueue(200);


/* handle the arp requests */
left_in_device  ->      Print("a")      ->      q1	->	sally::SSSMsg(2,2);
sally[0]	->	left_out_device;
sally[1]	->	right_out_device;
