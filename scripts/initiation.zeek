module Noise;

redef enum Notice::Type += {
    WireGuard_Initiation,
    };

event noise_initiation(c: connection, sender_index: int, unenc: string, enc_static: string, enc_timestamp: string, mac1: string, mac2: string)
        {
        if ( !c?$service ) { print "NOT SET"; }
        #print "INITIATION PACKET";
        local info: Info;
        info$ts  = network_time();
        info$uid = c$uid;
        info$id  = c$id;
        print c$service;
        #local myServcie = join_string_set(c$service,"-");
        #print fmt("Service Length: %d, %s",|c$service|, myService);
        if ( |c$service| == 1) {
          info$sender = fmt("%x",sender_index);
          info$unenc_ephemeral = bytestring_to_hexstr(unenc);
          info$enc_static = bytestring_to_hexstr(enc_static);
          info$enc_timestamp = bytestring_to_hexstr(enc_timestamp);
          info$mac1 = bytestring_to_hexstr(mac1);
          info$mac2 = bytestring_to_hexstr(mac2);
          info$msg_type = "INITIATION";
        NOTICE([$note=WireGuard_Initiation,
              $conn = c,
              $msg = "WireGuard Initiation Match",
              $sub = fmt("Sender: %s",info$sender)
              #$sub = fmt("Sender: %s", string_cat(info$sender))
              ]);
          }
        }

