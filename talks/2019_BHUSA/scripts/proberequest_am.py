# Guillaume Valadon <guillaume@valadon.net>

from scapy.all import *

# Specify the Wi-Fi interface
conf.iface = "mon0"

# Create the Answering Machine
class ProbeRequest_am(AnsweringMachine):
  function_name = "pram"

  mac = "00:11:22:33:44:55"

  def is_request(self, pkt):
    return Dot11ProbeReq in pkt

  def make_reply(self, req):

    rep = RadioTap()
    # Note: depending on your Wi-Fi card, you might need something else than RadioTap()
    rep /= Dot11(addr1=req.addr2, addr2=self.mac, addr3=self.mac, ID=RandShort(), SC=RandShort())
    rep /= Dot11ProbeResp(cap="ESS", timestamp=int(time.time()))
    rep /= Dot11Elt(ID="SSID",info="Scapy !")
    rep /= Dot11Elt(ID="Rates",info='\x82\x84\x0b\x16\x96')
    rep /= Dot11Elt(ID="DSset",info=orb(10))

    return rep

# Start the answering machine
ProbeRequest_am()()
