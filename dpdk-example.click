// address info for each of the interfaces
classifier0     :: Classifier(12/0806 20/0001, -, );
classifier1     :: Classifier(12/0806 20/0001, -, );
classifier2     :: Classifier(12/0806 20/0001, -, );
classifier3     :: Classifier(12/0806 20/0001, -, );
ipclassifier    :: IPClassifier(dst host 192.168.0.2);

in                 ::      FromDPDKDevice(0000:03:00.0, MTU 2500, JUMBO true);
out                ::      ToDPDKDevice(0000:03:00.0);

chip    :: MarkIPHeader(14);
chip1   :: MarkIPHeader(14);

encode :: XORMsg(3,0,1,1,1500);
decode :: XORMsg(3,1,1,1,1500);

/* handle the arp requests */

// x t u v
vls :: VlanSwitch(VLAN 15, VLAN 16, VLAN 17, VLAN 18);

in -> VLANDecap() -> vls;

vls[0] -> classifier0[0] -> Print("arp x") -> ARPResponder(192.168.0.2 192.168.0.0/24 00:08:a2:0d:e1:21) -> VLANEncap(VLAN_ID 15) -> out;
vls[1] -> classifier1[0] -> Print("arp t") -> ARPResponder(192.168.7.2 192.168.7.0/24 00:08:a2:0d:e1:21) -> VLANEncap(VLAN_ID 16) -> out;
vls[2] -> classifier2[0] -> Print("arp u") -> ARPResponder(192.168.7.2 192.168.7.0/24 00:08:a2:0d:e1:21) -> VLANEncap(VLAN_ID 17) -> out;
vls[3] -> classifier3[0] -> Print("arp v") -> ARPResponder(192.168.7.2 192.168.7.0/24 00:08:a2:0d:e1:21) -> VLANEncap(VLAN_ID 18) -> out;

classifier0[1] -> chip -> ipclassifier[0] -> encode;

classifier1[1] -> EtherRewrite(00:08:a2:0d:e1:21, 00:08:a2:0d:dc:b9) -> chip1 -> decode; // u
classifier2[1] -> EtherRewrite(00:08:a2:0d:e1:21, 00:08:a2:0d:e1:7f) -> chip1 -> decode; // t
classifier3[1] -> EtherRewrite(00:08:a2:0d:e1:21, 00:08:a2:0d:df:b1) -> chip1 -> decode; // v

encode[0] -> EtherRewrite(00:08:a2:0d:e1:21, 00:08:a2:0d:e1:7f) -> VLANEncap(VLAN_ID 16) -> out;
encode[2] -> EtherRewrite(00:08:a2:0d:e1:21, 00:08:a2:0d:df:b1) -> VLANEncap(VLAN_ID 18) -> out;
encode[1] -> EtherRewrite(00:08:a2:0d:e1:21, 00:08:a2:0d:dc:b9) -> VLANEncap(VLAN_ID 17) -> out;

decode -> EtherRewrite(00:08:a2:0d:e1:21, 00:08:a2:0d:de:9d) -> VLANEncap(VLAN_ID 15) -> out;
