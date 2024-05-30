//in_left ::   FromDevice( core );
//in_right  :: FromDevice( eth3 );
in_docker :: FromDevice( docker0 );
out_right :: ToDevice( eth3 ); 

classifierL :: Classifier(12/0800,-);

ipclassifierL    :: IPClassifier(
        dst host 10.10.5.2, // docker
        -,
        );

chip1  :: MarkIPHeader(14);
qright :: ThreadSafeQueue(1000);

// handle docker traffic
in_docker -> classifierL;
classifierL[0] -> chip1 -> ipclassifierL; // this is an ip packet
classifierL[1] -> Print("other") -> qright;
ipclassifierL[0]-> Print("docker to host") -> Discard;
ipclassifierL[1] -> Print("other") -> qright; 


qright -> out_right;
//qleft -> out_left;
