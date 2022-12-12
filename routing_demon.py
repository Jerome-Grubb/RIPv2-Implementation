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
