signature dpd_rdp {
  ip-proto == tcp
  payload /^\x03\x00.*Cookie: mstshash=/
  tcp-state originator
  event "RDP Detected"
}
