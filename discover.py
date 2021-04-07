from scapy.all import Ether, ARP, srp
import access_points

class discover():
    def discover(self):
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"),timeout=5, verbose = 0)
        return ans

    def signal(self):
        scan = access_points.get_scanner().get_access_points()
        return scan[0]["quality"]

    def start(self):
            for i,device in enumerate(self.discover()) : 
                print(f"{i+1} - {device[0]['ARP'].pdst}")
            print(f"Signal strength : {self.signal()} %")

if __name__ == "__main__" :
    discover().start()
 
