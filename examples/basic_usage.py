from nullsec_spoof.core import MACSpoofer,ARPSpoofer,DNSSpoofer
m=MACSpoofer()
for v in ["Apple","Samsung","Intel",None]:
    print(f"Vendor={v}: {m.random_mac(v)}")
a=ARPSpoofer()
print(f"\nARP plan: {a.generate_arp_spoof_plan('192.168.1.100','192.168.1.1')}")
d=DNSSpoofer()
print(f"DNS defenses: {d.analyze_dns_cache_poison()['defense']}")
