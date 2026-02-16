from trex.astf.api import *
import argparse

class Prof1():
    def get_profile(self, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('--cps', type=float, default=0.5, help='Connections per second per pcap')
        args = parser.parse_args(tunables)

        # Список всех профилей: (pcap_file, client_ip_start, client_ip_end, server_ip_start, server_ip_end)
        profiles = [
            ("prom_pcaps/iec104.pcap",         "192.168.3.1", "192.168.3.3",  "192.168.3.100", "192.168.3.100"),
            ("prom_pcaps/s7comm.pcap",         "192.168.4.1", "192.168.4.3",  "192.168.4.100", "192.168.4.100"),
            ("prom_pcaps/modbus.pcap",         "192.168.5.1", "192.168.5.3",  "192.168.5.100", "192.168.5.100"),
            ("prom_pcaps/opcua.pcap",         "192.168.6.1", "192.168.6.3",  "192.168.6.100", "192.168.6.100"),
            ("prom_pcaps/dnp3.pcap",           "192.168.7.1", "192.168.7.3",  "192.168.7.100", "192.168.7.100")
              ]

        cap_list = []
        
        for pcap_file, client_ip_start, client_ip_end, server_ip_start, server_ip_end in profiles:
            # Создаем IP генератор для каждого pcap
            ip_gen_c = ASTFIPGenDist(ip_range=[client_ip_start, client_ip_end], distribution="seq")
            ip_gen_s = ASTFIPGenDist(ip_range=[server_ip_start, server_ip_end], distribution="seq")
            ip_gen = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                               dist_client=ip_gen_c,
                               dist_server=ip_gen_s)
            
            # Добавляем pcap в список
            cap_list.append(ASTFCapInfo(
                file=pcap_file, 
                cps=args.cps,
                ip_gen=ip_gen
            ))

        return ASTFProfile(default_ip_gen=ip_gen, cap_list=cap_list)

def register():
    return Prof1()
