in_left   :: FromDevice( core );
out_left  :: ToDevice( core );

in_right  :: FromDevice( eth3 );
out_right :: ToDevice( eth3 ); 

classifierL     :: Classifier(12/0800,-);

ipclassifierL    :: IPClassifier(
        dst host 10.10.0.1, // sdcore2
        dst host 192.168.250.1, // core
        dst host 192.168.252.1, // access
        -,
        );

//portClassL :: IPClassifier(port 10001, port 10002, -)
//portClassL :: IPClassifier(port 10001, -)
//portClassL :: IPClassifier(port 11000, -)

upfL  :: UPF(true, 10.10.5.2, 10.10.0.1); // first value ignored
chip1 :: MarkIPHeader(14);
qright   :: ThreadSafeQueue(1000);
qleft   :: ThreadSafeQueue(1000);

in_left -> classifierL;
classifierL[0] -> chip1 -> ipclassifierL; // this is an ip packet
classifierL[1] -> Print("other") -> Discard; // send back out


//ipclassifierL[0] -> portClassL;
//portClassL[0] -> Print("no touchy L") -> EtherRewrite(36:a8:2e:ea:c9:6c, 04:70:00:00:02:01) -> qright;
//portClassL[1] -> EtherRewrite(04:70:00:00:02:01, 04:70:00:00:00:02) -> IPAddrPairRewriter(pattern 10.10.5.2 - 0 0) ->  qright;
//portClassL[0] -> Print("no touchy L") -> qright;
//portClassL[1] -> upfL -> EtherRewrite(04:70:00:00:02:01, 04:70:00:00:00:02) -> IPAddrPairRewriter(pattern 10.10.5.2 - 0 0) ->  qright;
ipclassifierL[0] -> upfL -> EtherRewrite(04:70:00:00:02:01, 04:70:00:00:00:02) -> IPAddrPairRewriter(pattern 10.10.5.2 - 0 0) ->  qright;
ipclassifierL[1] -> Discard; // destined for this interface
ipclassifierL[2] -> Discard; // needs to go back to access network
ipclassifierL[3] -> Discard; // dont know what to do with

classifierR     :: Classifier(12/0800, -);

ipclassifierR  :: IPClassifier(
        dst host 10.10.5.2, // sdcore1
        dst host 192.168.250.1, // core
        dst host 192.168.252.1, // access
        -,
        );

//portClassR :: IPClassifier(port 10001, -);
//portClassR :: IPClassifier(port 11000, -);

// actual gnbsim
upfR  :: UPF(false, 10.10.0.1, 10.10.5.2, PREFIX 172.250.0.0);

// testing gnbsim
// upfR  :: UPF(false, 10.10.0.1, 10.10.5.2, PREFIX 172.26.0.0);
chip2 :: MarkIPHeader(14);

in_right -> classifierR;
classifierR[0] -> chip2 -> ipclassifierR;
classifierR[1] -> IPPrint("other") -> Discard;


// 172.26.0.2 02:42:ac:1a:00:02 gnbsim 
//ipclassifierR[0] -> upfR -> EtherRewrite(04:70:00:00:02:01, 02:42:ac:1a:00:02) ->  IPPrint("post", CONTENTS true, ETHER true, LENGTH true) -> qleft;

// 172.250.0.30 n3 ip addr
//ipclassifierR[0] -> portClassR;


//portClassR[0] -> Print("no touchy R") -> qleft;

//portClassR[0] -> Print("no touchy R") -> EtherRewrite(36:a8:2e:ea:c9:6c, 04:70:00:00:02:01) ->  qleft;
//portClassR[1] -> upfR -> EtherRewrite(04:70:00:00:02:01, 36:a8:2e:ea:c9:6c) ->  IPPrint("post", CONTENTS true, ETHER true, LENGTH true) -> qleft;

ipclassifierR[0] -> upfR -> EtherRewrite(04:70:00:00:02:01, 36:a8:2e:ea:c9:6c) ->  IPPrint("post", CONTENTS true, ETHER true, LENGTH true) -> qleft;

ipclassifierR[1] -> Discard;
ipclassifierR[2] -> Discard;
ipclassifierR[3] -> Discard;

qright -> out_right;
//qother -> out_other;
qleft -> out_left;
