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
