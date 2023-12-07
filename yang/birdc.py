import cbor
import json
import sys
import os
import socket, struct
import datetime


class Command:
    num = -1
    def addr_to_str(self, addr):
        return '.'.join(str(c) for c in addr.value)

    def prefix_to_str(self, addr):
        str_addr = '.'.join(str(c) for c in addr.value[1])
        str_addr = str_addr + "/" +addr.value[0]
        return str_addr

    def print_answer(self, answer):
        print(answer)

class Memory(Command):
    num = 1
    def nums_to_str(self, answer, key):

        e = answer["show_memory:message"]["body"][key]["effective"]
        o = answer["show_memory:message"]["body"][key]["overhead"]
        j_e = " B"
        j_o = " B"
        if e > 9999:
            e = e/1000
            j_e = "kB"
        if o > 9999:
            o = o/1000
            j_o = "kB"
        return f"{e:>7} {j_e}   {o:>7} {j_o}"
    
    def print_answer(self, answer):
        print()
        print("BIRD memory usage")
        keys = answer["show_memory:message"]["body"].keys()
        first_column_width = len("route attributes  ")
        print(" " * (first_column_width+4), "Effective    ", "Overhead")
        for key in keys:
            name = key.replace("_", " ")
            print(name,":", " "*(first_column_width - len(name)), self.nums_to_str(answer, key))


class Status(Command):
    num = 0

    def print_answer(self, answer):
        print(answer)
        print()
        print("BIRD", answer["show_status:message"]["version"])
        for key in answer["show_status:message"]["body"].keys():
            name = key.replace("_", " ")
            if key == "router_id":
                print(name, self.addr_to_str( answer["show_status:message"]["body"][key]))
            elif key in "server_time last_reboot last_reconfiguration":
                print(name, datetime.datetime.fromtimestamp(answer["show_status:message"]["body"][key]))
            else:
                print(name, answer["show_status:message"]["body"][key])
        print(answer["show_status:message"]["state"])


class Symbols(Command):
    num = 2

    def print_answer(self, answer):
        print()
        for item in answer["show_symbols:message"]["table"]:
            print(f"{item['name']:<15} {item['type']}")


class Ospf(Command):
    num = 3

    def print_lsa_router(self, area):
        print ("\trouter", self.addr_to_str(area['router']))
        print("\t\tdistance", area['distance'])
        if ('vlink' in area.keys()):
            for vlink in area['vlink']:
                print(f"\t\tvlink {self.addr_to_str( vlink['vlink'])} metric {vlink['metric']}")
        if ('router_metric' in area.keys()):
            for router in area['router_metric']:
                print(f"\t\trouter {self.addr_to_str( router['router'])} metric {router['metric']}")
        for network in area['network']:
            addr = self.addr_to_str(network['network'])
            if('nif' in network):
                print(f"\t\tnetwork [{addr}-{network['nif']}] metric {network['metric']}")
            elif('len' in area.keys()):
                print(f"\t\tnetwork {addr}/{network['len']} metric {network['metric']}")
            else:
                print(f"\t\tnetwork [{addr}] metric {network['metric']}")
        if ('stubnet' in area.keys()):
            for stubnet in area['stubnet']:
                print(f"\t\tstubnet {self.addr_to_str(stubnet['stubnet'])}/{stubnet['len']} metric {stubnet['metric']}")

    def print_lsa_network(self, area):
        if ('ospf2' in area.keys()):
            print(f"\tnetwork {self.addr_to_str(area['ospf2']['network'])}/{area['ospf2']['optx']}")
            print(f"\t\tdr {self.addr_to_str(area['ospf2']['dr'])}")
        elif ('ospf' in area.keys()):
            print(f"\tnetwork [{self.addr_to_str(area['ospf']['network'])}-{area['ospf']['lsa_id']}]")
        print("\t\tdistance", area['distance'])
        for router in area['routers']:
            print(f"\t\trouter {self.addr_to_str(router['router'])}")

    def print_lsa_sum_net(self, area):
        print(f"\t\txnetwork {self.prefix_to_str(area['net'])} metric {area['metric']}")

    def print_lsa_sum_rt(self, area):
        print(f"\t\txrouter {self.addr_to_str(area['router'])} metric {area['metric']}")

    def print_lsa_external(self, area):
        if('lsa_type_num' in area.keys()):
            print(f"\t\t{area['lsa_type']} {self.prefix_to_str(area['rt_net'])} metric{area[lsa_type_num]} {area['metric']}%s%s")
        else:
            print(f"\t\t{area['lsa_type']} {self.prefix_to_str(area['rt_net'])} metric {area['metric']}{area['via']}{area['tag']}")

    def print_lsa_prefix(self, area):
        for prefix in area['prefixes']:
            if 'metric' in prefix.keys():
                print(f"\t\tstubnet {self.prefix_to_str(prefix['stubnet'])} metric {prefix['metric']}")

    def print_answer(self, answer):
        print()
        if ("error" in answer["show_ospf:message"].keys()):
            print("error: ", answer["show_ospf:message"]["error"])
            return
        if ("not implemented" in answer["show_ospf:message"].keys()):
            print("not implemented: ", answer["show_ospf:message"]["not implemented"])
            return
        for area in answer["show_ospf:message"]["areas"]:
            if 'area' in area.keys():
                print ("area", self.addr_to_str(area['area']))
            print()
            if 'lsa_router' in area.keys():
                self.print_lsa_router(area['lsa_router'])
            elif 'lsa_network' in area.keys():
                self.print_lsa_network(area['lsa_network'])
            elif 'lsa_sum_net' in area.keys():
                self.print_lsa_sum_net(area['lsa_sum_net'])
            elif 'lsa_sum_rt' in area.keys():
                self.print_lsa_sum_rt(area['lsa_sum_rt'])
            elif 'lsa_external' in area.keys():
                self.print_lsa_external(area['lsa_external'])
            elif 'lsa_prefix' in area.keys():
                self.print_lsa_prefix(area['lsa_prefix'])
        if('asbrs' in area.keys()):
            for asbr in area['asbrs']:
                if('other_ABSRs' in asbr.keys()):
                    print("other ASBRs")
                print("other ASBRs")
                print(f"\trouter {self.addr_to_str(asbr['router'])}")

command_dictionary = {"status":0, "memory":1, "symbols":2, "ospf":3}

def get_command_class(string):
    if string == "status":
        return Status()
    if string == "memory":
        return Memory()
    if string == "symbols":
        return Symbols()
    if string == "ospf":
        return Ospf()
    raise Exception(f"Command {string} not known. Expected status, memory, symbols or ospf")

def run_on_machine(dev, cmd):
    ws = os.system(f"ip netns exec {dev} {cmd}")
    if os.WIFEXITED(ws):
        ec = os.WEXITSTATUS(ws)
    else:
        ec = False

    if ec != 0:
        raise Exception(f"Command {cmd} exited with exit code {ws}")


arguments = sys.argv
if (len(sys.argv) <= 2):
    raise Exception("Expected command, no argunents given.")
if (len(sys.argv) == 3):
    raise Exception(f"only one ({sys.argv[2]}) command given, that is not implemented")
if(sys.argv[2] != "show"):
    raise Exception(f"Expected 'dev show status/memory/symbols/ospf', unknown {sys.argv[2]}.")
comm = get_command_class(sys.argv[3])

command = {"command:do":{"command":comm.num, "args":[]}}
for i in range (4, len(sys.argv)):
    command["command:do"]["args"].append({"arg": sys.argv[i]})
print(command)

with open(os.getcwd()+"/command.cbor", "wb") as of:
    cbor.dump(command, of)

run_on_machine(sys.argv[1], f"cat command.cbor | sudo socat UNIX-CONNECT:{os.getcwd()}/bird-yang.ctl STDIO > answer.cbor")


with open("answer.cbor", "br") as cbor_file:
    answer = cbor.load(cbor_file)
    
    comm.print_answer(answer)
