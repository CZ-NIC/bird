#! /bin/env python3

"""
A very simple script used to test that BIRD does not segfaults on randomly split
AgentX PDUs.
"""

import socket
import random
import time
import math

ADDRESS = "127.0.0.1"
PORT = 5000
AGENTX_MASTER_PORT = 705

def chunks(lst, n):
    l = len(lst)
    for i in range(0, l, n):
        yield lst[i: min(i+n, l)]

def print_msg(header, msg, total):
    print(header, "{}/{}".format(len(msg), total))
    for line in chunks(msg, 16):
        print("  ", end="")
        for char in line:
            print("0x{:02x} ".format(char), end="")

        print()

def create_listen():
    tun = socket.socket()
    print(f"Binding to port {PORT} on {ADDRESS}")
    tun.bind((ADDRESS, PORT))
    print(f"Listening on {ADDRESS} port {PORT}")
    tun.listen(2)

    return tun

def io_loop(rx, tx):
    while True:
        try:
            to_master = rx.recv(8192)
        except BlockingIOError:
            to_master = None

        try:
            to_subagent = tx.recv(8192)
        except BlockingIOError:
            to_subagent = None

        if to_master is not None and len(to_master) > 0:
            print_msg("S=>M: ", to_master, len(to_master))
            tx.send(to_master)

        if to_subagent is not None and len(to_subagent) > 0:
            limit = 5 * len(to_subagent) / 100
            part_len = random.randint(math.ceil(limit),
                       math.floor(len(to_subagent) - limit))

            print(f"M->S: {len(to_subagent[:part_len])}/{len(to_subagent)}")
            rx.send(to_subagent[:part_len])
            time.sleep(0.4)
            print_msg("M=>S: ", to_subagent, len(to_subagent))
            rx.send(to_subagent[part_len:])

        time.sleep(0.02)

def safe_io_loop(tun):
    while True:
        try:
            rx, addr = tun.accept()
            print("Subagent connected")

            tx = socket.socket()
            tx.connect((ADDRESS, AGENTX_MASTER_PORT))
            print("Connected to master agent")

            rx.setblocking(False)
            tx.setblocking(False)

            io_loop(rx, tx)
        except BrokenPipeError:
            rx.close()
            tx.close()

def main():
    with create_listen() as listening:
        safe_io_loop(listening)

if __name__ == '__main__':
        main()
