import pysipp
import argparse

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--remote_host',type=str, required=True,
            help='Remote host')
    parser.add_argument('--remote_port',type=int, help='Remote Port')
    parser.add_argument('--local_host',type=str, default="127.0.0.1",
            help='Local Host')
    parser.add_argument('--local_port',type=int, default=5000,
             help='Remote host')
    parser.add_argument('--username',type=str, help='Remote host')
    parser.add_argument('--auth_password',type=str, help='Remote host')
    parser.add_argument('--scen_dir',type=str, help='Path to the scenario directory')
    parser.add_argument('--transport',type=str, help='Transport TCP or UDP')
    args = parser.parse_args()
    return args

class SIP():
    def __init__(self, **kwargs):
        args = kwargs.get('args')
        self.scen = None
        self.local_host = args.local_host
        self.local_port = args.local_port
        self.remote_host = args.remote_host
        self.remote_port = args.remote_port
        self.username = args.username
        self.auth_password = args.auth_password
        self.scen_dir = args.scen_dir
        self.transport = args.transport

    def execute_scenario(self):
        self.scen = pysipp.scenario(dirpath=self.scen_dir, proxyaddr=(self.remote_host, self.remote_port))
        for agent in self.scen._agents:
            agent.local_host = self.local_host
            agent.local_port = self.local_port
        self.scen.remote_host = self.remote_host
        self.scen.remote_port = self.remote_port
        self.scen.uri_username = self.username
        self.scen.auth_password = self.auth_password
        self.scen.transport = self.transport
        self.scen()

if __name__ == '__main__':
    args = parse_args()
    sip = SIP(args=args)
    sip.execute_scenario()
