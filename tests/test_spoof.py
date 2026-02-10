import unittest,sys,os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"..","src"))
from nullsec_spoof.core import MACSpoofer,ARPSpoofer,DNSSpoofer

class TestMAC(unittest.TestCase):
    def test_random(self):
        s=MACSpoofer()
        m=s.random_mac()
        self.assertEqual(len(m),17)
    def test_vendor(self):
        s=MACSpoofer()
        m=s.random_mac("Apple")
        self.assertTrue(m.startswith("A4:83:E7"))

class TestARP(unittest.TestCase):
    def test_packet(self):
        a=ARPSpoofer()
        p=a.build_arp_packet("aa:bb:cc:dd:ee:ff","192.168.1.1","11:22:33:44:55:66","192.168.1.100")
        self.assertEqual(p["opcode"],2)

class TestDNS(unittest.TestCase):
    def test_response(self):
        d=DNSSpoofer()
        r=d.build_response("example.com","1.2.3.4")
        self.assertEqual(r["type"],"A")

if __name__=="__main__": unittest.main()
