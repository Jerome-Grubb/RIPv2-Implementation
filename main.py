import sys

from routing_demon import Router, HOST
from config_parser import parse


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
