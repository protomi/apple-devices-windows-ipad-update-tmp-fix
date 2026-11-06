## Local relay working around error 1109 / 06B4.0000 in Apple Devices for Windows.

During an iPhone/iPad update or restore, Apple Devices downloads the AEA decryption key of the
system image from https://wkms-public.apple.com/fcs-keys/..., which redirects to Apple's CDN
fcs-keys-pub-prod.cdn-apple.com. The CDN sends its TLS 1.3 session tickets and the HTTP response
in the same packet, and Apple Devices' own TLS stack (CFNetwork.dll) then stalls until it times
out. This relay forwards the connection to the real CDN (TLS stays end-to-end, no certificate is
touched) and hands the TLS records to Apple Devices one at a time, with a short pause in between.

### Usage:
  1. hosts file line (as administrator):  127.0.0.1 fcs-keys-pub-prod.cdn-apple.com
  2. ipconfig /flushdns
  3. python apple_key_relay.py      (keep it open during the update; Ctrl+C to quit)
  4. after the update remove the hosts line and run ipconfig /flushdns again

**Use at your own risk. The code is provided as is with no guarantee** (it worked for me, the software to be fixed is not open source, I can't do more)
