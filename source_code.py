# authors: jfg50, 26612998 and wih15, 59709512

import sys

from routing_demon import Router, HOST
from config_parser import parse


# =============================================
# This is the main file, which contains sets up the the router, and starts the loop
# =============================================

def main():
    # print(sys.version_info[0])
    assert len(sys.argv) >= 2, "No config file given"
    config_fp = sys.argv[1]
    config_dict = parse(config_fp)
    router_id, input_ports, outputs = config_dict.values()
    router = Router(router_id, input_ports, outputs, {})
    router.initialise_table()
    router.start()


if __name__ == "__main__":
    main()

# =============================================
# This is the config_parser file
# =============================================

from configparser import ConfigParser


def parse(c_file_name):
    # Dictionary to be returned
    c_dict = {}

    # Create ConfigParser object for the input filepath that will be used to extract the information
    config_obj = ConfigParser()
    with open(c_file_name) as filepath:
        config_obj.read_file(filepath)
    config = config_obj["router_config"]

    # Extracts the router ID and asserts that it is within the allowed range (1 - 64000)
    router_id = int(config["router-id"])
    assert 1 <= router_id <= 64000, "Router ID is not an integer between 1 and 64000"
    c_dict["router-id"] = router_id

    # Extracts the input ports and asserts that they are all within the allowed range (1024 - 64000)
    input_ports = config["input-ports"]
    input_port_list = input_ports.split(", ")
    input_port_list = list(map(int, input_port_list))  # Converts all ports to integers
    for input_port in input_port_list:
        assert 1024 <= input_port <= 64000, "An input port is not an integer between 1024 and 64000"
    c_dict["input-ports"] = input_port_list

    # Extracts the output ports, asserts that they are all within the allowed range (1024 - 64000) and that the
    # output port is present in the input port list
    outputs_list = []
    output_ports = config["output_ports"].split(', ')
    for output_port in output_ports:
        output_port_split = output_port.split('-')
        dest_port, dest_val, dest_router_id = map(int, output_port_split)
        assert 1024 <= dest_port <= 64000, "An output port is not an integer between 1024 and 64000"
        assert dest_port not in c_dict["input-ports"]
        outputs_list.append([dest_port, dest_val, dest_router_id])
    c_dict["outputs"] = outputs_list

    return c_dict


# =============================================
# This is the file containing all methods relating to packets
# =============================================

VERSION = 2
COMMAND = 2
ADF = 2


def packet_header(packet, router_id):
    packet.extend(COMMAND.to_bytes(1, "big"))

    packet.extend(VERSION.to_bytes(1, "big"))

    packet.extend(router_id.to_bytes(2, "big"))

    return packet


def packet_payload(packet, routing_table):
    for i, routes in enumerate(routing_table.values()):
        zero = 0
        packet.extend(ADF.to_bytes(2, "big"))
        packet.extend(zero.to_bytes(2, "big"))
        packet.extend(routes.destination_id.to_bytes(4, "big"))
        packet.extend(zero.to_bytes(4, "big"))
        packet.extend(zero.to_bytes(4, "big"))
        packet.extend(routes.metric.to_bytes(4, "big"))
    return packet


def validate(packet):
    is_valid = True
    if packet[0] != 2:
        print("The version number of {} is incorrect. The version number must be 2".format(packet[0]))
        is_valid = False

    if packet[1] != 2:
        print("The command number of {} is incorrect. It must be 2, as this is a response packet".format(packet[1]))
        is_valid = False

    if ((packet[2] << 8) + packet[3]) > 64000 or ((packet[2] << 8) + packet[3]) < 1:
        print("A routers Id must be between 1 and 6400. This routers id is {}".format(((packet[2] << 8) + packet[3])))
        is_valid = False
    if len(packet) > 4:
        if ((packet[4] << 8) + (packet[5])) != 2:
            print("The address family identifier needs to be 2")
            is_valid = False

        if packet[6] != 0 or packet[7] != 0 or packet[12] != 0 or packet[13] != 0 or packet[14] != 0 or packet[
            15] != 0 or \
                packet[16] != 0 or packet[17] != 0 or packet[18] != 0 or packet[19] != 0:
            print("The bytes 6 to 7, and 12 to 19 need to be 0")
            is_valid = False

        if (packet[8] << 8 * 3) + (packet[9] << 8 * 2) + (packet[10] << 8) + (packet[11]) > 64000 or (
                packet[8] << 8 * 3) + (packet[9] << 8 * 2) + (packet[10] << 8) + (packet[11]) < 1:
            print("A routers Id number must be between 1 and 64000. This routers Id number is {}".format(
                ((packet[8] << 8 * 3) + (packet[9] << 8 * 2) + (packet[10] << 8) + (packet[11]))))
            is_valid = False

        if ((packet[20] << 8 * 3) + (packet[21] << 8 * 2) + (packet[22] << 8) + (packet[23])) < 1:
            print("A routers metric cannot be below 1")
            is_valid = False

    return is_valid


def retrieve_data(packet, index, size):
    data = packet[index:index + size]
    return int.from_bytes(data, byteorder='big')


# =============================================
# This is the file containing all methods relating to routing table entries
# =============================================

class Entry(object):
    def __init__(self, destination_id, metric, next_port, next_address):
        self.destination_id = destination_id
        self.metric = metric
        self.next_address = next_address
        self.next_port = next_port
        self.timeout = 0
        self.garbage_timer = 0
        self.garbage_timer_flag = False

    def get_dest_id(self):
        return self.destination_id

    def view_route(self):
        print("destination address:" + str(self.destination_id) + ", metric: " + str(
            self.metric) + ", next routers id:" + str(self.next_address) + ", next port num: " + str(
            self.next_port) + ", timeout timer: " + str(self.timeout) + ", garbage timer:" + str(
            self.garbage_timer) + ", garbage flag:" + str(self.garbage_timer_flag))

    def update_garbage_timer(self):
        self.garbage_timer += 1

    def update_route_metric(self, value):
        self.metric = value

    def update_timeout(self):
        self.timeout += 1

    def reset_timeout(self):
        self.timeout = 0

    def reset_garbage_timer(self):
        self.garbage_timer = 0

    def set_garbage_flag(self, boolean):
        self.garbage_timer_flag = boolean

    def poison_reverse(self):
        self.metric = 16


# =============================================
# This is the file containing all methods relating to the routing demon.
# =============================================

import select
import socket

from Packet import *
from Table_Entry import Entry
import time
import numpy as np
import random as random

HOST = '127.0.0.1'  # IP for local host


class Router(object):

    def __init__(self, router_id, input_ports, outputs, routing_table):
        self.router_id = router_id
        self.input_ports = input_ports
        self.outputs = outputs

        self.update_time = 30
        self.time = 0

        self.routing_table = routing_table

        self.sockets = []

        # For debugging purposes
        self.neighbours = {}
        for output in self.outputs:
            neighbour_id = output[2]
            neighbour_metric = output[1]
            neighbour_port = output[0]
            self.neighbours[neighbour_id] = [neighbour_port, neighbour_metric]

    def create_sockets(self):
        for ports in self.input_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Creating UDP socket
                sock.bind((HOST, ports))
                self.sockets.append(sock)
                print("Successfully opened a socket")
            except Exception as error:
                for j in range(len(self.sockets)):
                    closed_socket = self.sockets[j]
                    closed_socket.close()
                print("{0}: There was an error opening a socket on the port {1}".format(error, ports))
                exit()

    def initialise_table(self):
        pass  # Pretty sure we aren't supposed to add routes to the table until a packet is received

    def update_timer(self):
        if self.time >= self.update_time:
            self.send_update()
            self.time = np.random.normal(2)  # random initial time using Gaussian distribution (scale=2)
        self.time += 1

    def update_entry_timers(self):
        print("\n*******************************")
        ids_to_delete = []
        needs_triggered_update = False
        if len(self.routing_table.values()) == 0:
            print("EMPTY ROUTING TABLE")
        for route in self.routing_table.values():
            route.view_route()
            if route.garbage_timer_flag:
                if route.garbage_timer >= 120:
                    ids_to_delete.append(route.get_dest_id())

                else:
                    route.update_garbage_timer()
            else:
                if route.timeout >= 180 or route.metric > 15:
                    route.update_route_metric(16)
                    route.set_garbage_flag(True)
                    route.poison_reverse()
                    route.reset_timeout()
                    route.update_garbage_timer()
                    needs_triggered_update = True
                else:
                    route.update_timeout()
        if needs_triggered_update:
            # needs_triggered_update = False  # unnecessary?
            self.triggered_update()
        for dest_id in ids_to_delete:
            self.delete_entry(dest_id)

        print("*******************************")

    def triggered_update(self):
        time_until_update = random.randint(0, 5)
        # If there is about to be a periodic update, then don't send a triggered update
        if time_until_update >= (self.update_time - self.time):
            pass
        else:
            for i in self.outputs:
                packet = bytearray()
                packet_head = packet_header(packet, self.router_id)
                made_packet = packet_payload(packet_head, self.routing_table)
                self.sockets[0].sendto(made_packet, (HOST, int(i[0])))
        print("TRIGGERED UPDATE SENT")

    # This will send a response message to all peer routers containing the routing table
    def send_update(self):
        for i in self.outputs:
            routing_table = self.routing_table
            sh_routing_table = self.split_horizon(i, routing_table)
            packet = bytearray()
            packet_head = packet_header(packet, self.router_id)
            made_packet = packet_payload(packet_head, sh_routing_table)
            self.sockets[0].sendto(made_packet, (HOST, int(i[0])))
            print("Sent")

    def split_horizon(self, i, routing_table):
        sh_routing_table = {}
        output_id = i[2]
        for dest_id, entry in routing_table.items():
            next_hop = entry.next_address
            if next_hop != output_id:
                sh_routing_table[dest_id] = entry
        return sh_routing_table

    # This will receive incoming updates from peer routers
    def receive_updates(self):
        try:
            ready_socks, _, _ = select.select(self.sockets, [], [], 0)
        except Exception as error:
            for j in range(len(self.sockets)):
                closed_socket = self.sockets[j]
                closed_socket.close()
            print("{0}: There was an error opening a socket on the port {1}".format(error, self.input_ports))
            exit()
        for sock in ready_socks:
            payload, addr = sock.recvfrom(4096)
            self.update_table(payload)

    def update_table(self, packet):

        is_valid = validate(packet)
        existing_direct_route = None
        needs_triggered_update = False
        if is_valid:
            parent, entries_list = self.process_packet(packet)

            for port in self.outputs:
                if port[2] == parent:
                    existing_direct_route = port
            if existing_direct_route is not None:
                ex_dir_route_port = existing_direct_route[0]
                ex_dir_route_metric = existing_direct_route[1]
                ex_dir_route_id = existing_direct_route[2]

                if self.routing_table.get(ex_dir_route_id) is None or \
                        (ex_dir_route_metric < self.routing_table[ex_dir_route_id].metric):  # This line is just checking if the direct
                    # route from the current router to the parent router exists and has the right metric

                    entry = Entry(ex_dir_route_id, ex_dir_route_metric, ex_dir_route_port,
                                  ex_dir_route_id)

                    self.routing_table[ex_dir_route_id] = entry

                elif ex_dir_route_metric >= self.routing_table[ex_dir_route_id].metric and \
                        ex_dir_route_id == self.routing_table[ex_dir_route_id].destination_id:  # This statement is for resetting the timers for the direct route, as it has been used
                    self.routing_table[ex_dir_route_id].reset_timeout()
                    self.routing_table[ex_dir_route_id].reset_garbage_timer()
                    self.routing_table[ex_dir_route_id].set_garbage_flag(False)

            for entry in entries_list:
                existing_route = self.routing_table.get(entry.destination_id)
                if existing_route is None:
                    if entry.metric < 16:  # If the route is valid and there is no existing route in place for this router already, add it to the table
                        if entry.destination_id != self.router_id:
                            self.routing_table[entry.destination_id] = entry

                    elif entry.metric >= 16:
                        print(
                            "This packet is invalid as the route has reached a metric of 16 hops, and will consequently be dropped")
                        pass

                else:  # If there is already a route that exists
                    if existing_route.next_address == entry.next_address:  # This checks if the pre existing route is the same as our new route
                        self.routing_table[entry.destination_id].reset_timeout()
                        if entry.metric != existing_route.metric and existing_route.metric < 16:
                            self.routing_table[existing_route.destination_id].metric = entry.metric
                            self.routing_table[existing_route.destination_id].set_garbage_flag(False)
                            self.routing_table[existing_route.destination_id].reset_garbage_timer()
                            if entry.metric >= 16:
                                self.routing_table[existing_route.destination_id].set_garbage_flag(True)
                                self.routing_table[existing_route.destination_id].update_route_metric(16)
                                needs_triggered_update = True
                        elif entry.metric != existing_route.metric and existing_route.metric >= 16:
                            pass
                    elif entry.metric < existing_route.metric:
                        self.routing_table[entry.destination_id] = entry
        if needs_triggered_update:
            self.triggered_update()

    def process_packet(self, packet):
        existing_route = None
        index = 0
        entries = []
        packet_length = len(packet)
        index += 2
        parent_id = retrieve_data(packet, index, 2)
        index += 2
        while index < packet_length:
            index += 4
            destination_id = retrieve_data(packet, index, 4)
            index += 12
            metric = retrieve_data(packet, index, 4)
            index += 4
            for port in self.outputs:
                if port[2] == parent_id:
                    existing_route = port
            entry = Entry(destination_id, (metric + existing_route[1]), existing_route[0], parent_id)
            entries.append(entry)
        return parent_id, entries

    def delete_entry(self, key):
        del self.routing_table[key]

    def start(self):
        self.create_sockets()
        while True:
            self.update_timer()
            self.update_entry_timers()
            self.receive_updates()
            time.sleep(1)
