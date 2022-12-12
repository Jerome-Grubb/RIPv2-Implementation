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
        print("destination address:" + str(self.destination_id) + ", metric: " + str(self.metric) + ", next routers id:" + str(self.next_address) + ", next port num: " + str(self.next_port) + ", timeout timer: " + str(self.timeout) + ", garbage timer:" + str(self.garbage_timer) + ", garbage flag:" + str(self.garbage_timer_flag))

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

