module Noise;

redef enum Notice::Type += {
    WireGuard_Response,
    };


event noise_response(c: connection, sender: int, receiver: int, unenc: string, enc_nothing: string, mac1: string, mac2: string)
{
  print fmt("%s",encode_base64(unenc));
  local info: Info;
  info$ts  = network_time();
  info$uid = c$uid;
  info$id = c$id;
  info$msg_type = "RESPONSE";
  info$sender = fmt("%x", sender);
  info$receiver = fmt("%x",receiver);
  info$unenc_ephemeral = bytestring_to_hexstr(unenc);
  info$enc_nothing = bytestring_to_hexstr(enc_nothing);
  info$mac1 = bytestring_to_hexstr(mac1);
  info$mac2 = bytestring_to_hexstr(mac2);
  NOTICE([$note=WireGuard_Response,
		$conn = c,
                $msg = "WireGuard Initiation Match",
                $sub = fmt("Sender: %s, Unenc: %s",info$sender, encode_base64(unenc))
         ]);
}
