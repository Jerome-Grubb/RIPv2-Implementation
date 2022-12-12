VERSION = 2
COMMAND = 2
ADF = 2


def packet_header(packet, router_id):
    packet.extend(COMMAND.to_bytes(1, "big"))

    packet.extend(VERSION.to_bytes(1, "big"))

    packet.extend(router_id.to_bytes(2, "big"))

    return packet

    # Creates a copy of the routing table to use as the packets payload
    # TODO check for split horizon


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

        if packet[6] != 0 or packet[7] != 0 or packet[12] != 0 or packet[13] != 0 or packet[14] != 0 or packet[15] != 0 or \
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
