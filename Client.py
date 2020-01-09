from time import *
from socket import *
import hashlib
import logging
from struct import *

TEAM_NAME_LENGTH = 32
HASHED_TEAM_NAME = "Avner"
BYTES_TILL_LENGTH = 74
NACK_FORMAT = "32s B 40s B"
ACK_FORMAT = "32s B 40s B {0}s"
DISCOVER_FORMAT = "32s B"
HASHED_MSG_LENGTH = 40
BUFFER_SIZE = 1024
TIMEOUT = 15
OFFER_TIMEOUT = 2
DISCOVER = 1
ACK = 4
NACK = 5
REQUEST = 3


def welcome_user_and_get_hash(self):
    print("Welcome to Avner, Please enter the hash:")
    self.input_hash = input()


def get_input_hash_and_length(self):
    not_found = True
    while not_found:
        print("Please enter the input string length:")
        try:
            self.length = int(input())
            not_found = False
        except ValueError:
            logging.error("Illegal input!")


def convert_str_to_hex(str_to_covert):
    num = 0
    for c in str_to_covert:
        if c < 'a' or c > 'z':
            raise
        num *= 26
        num += ord(c) - ord('a')
    return num


def convert_hex_to_str(hex_to_convert, length):
    s = ""
    while hex_to_convert > 0:
        c = int(hex_to_convert % 26)
        s = chr(c + ord('a')) + s
        hex_to_convert = int(hex_to_convert / 26)
        length -= 1

    while length > 0:
        s[0] = 'a'
        length -= 1
    return s


def split_data_to_servers(num_of_servers, message_len):
    domains = [""] * (num_of_servers * 2)
    first = last = ""
    last_element_idx = (num_of_servers * 2) - 1
    summer = 0
    for i in range(message_len):
        first += "a"
        last += "z"

    total = convert_str_to_hex(last)
    per_server = int(total / num_of_servers)
    domains[0] = first
    domains[last_element_idx] = last

    num_of_domains = len(domains)
    for i in range(num_of_domains)[1:num_of_domains - 2]:
        summer += per_server
        domains[i] = convert_hex_to_str(summer, message_len)
        summer += 1
        domains[i + 1] = convert_hex_to_str(summer, message_len)
    return domains


def ask_hash_solution(self):
    discover_self(self)
    num_of_servers = len(self.servers)
    if num_of_servers == 0:
        return
    domains = split_data_to_servers(num_of_servers, self.length)
    request_messages(self, domains)
    self.sock.settimeout(TIMEOUT)

    num_of_answers = 0

    while True and num_of_answers < len(self.servers):
        logging.info("waiting for solution...")
        try:
            (data, addr) = self.sock.recvfrom(BUFFER_SIZE)
            num_of_answers += 1
            logging.info("Got an answer from server: %s. analyzing data...", addr)
            if data and analyze_data(data, addr):
                return
        except timeout:
            logging.info("Timeout exceeded when waiting for answer")
            break
    logging.info("all servers answered.")


def unpack_data(data):
    team_name, op_code, hashed_str, length = unpack(NACK_FORMAT, data[:BYTES_TILL_LENGTH])
    if op_code == ACK:
        team_name, op_code, hashed_str, length, result = unpack(ACK_FORMAT.format(length), data)
        return team_name, op_code, hashed_str, length, result
    else:
        team_name, op_code, hashed_str, length = unpack(NACK_FORMAT.format(length), data[:BYTES_TILL_LENGTH])
        return team_name, op_code, hashed_str, length, ""


def analyze_data(data, addr):
    team_name, op_code, hashed_str, length, result = unpack_data(data)
    if op_code == ACK:
        result = result.decode()[:length]
        logging.info("Got ACK from %s", addr)
        logging.info("The input string is %s", result)
        return True
    else:
        if op_code == NACK:
            logging.info("Got NACK from %s", addr)
            return False


def request_messages(self, domains):
    i = 0
    for server in self.servers:
        if i >= len(domains):
            break
        self.FORMAT = "32s B 40s B {0}s {0}s".format(self.length)
        message = pack(self.FORMAT, HASHED_TEAM_NAME.encode(), REQUEST, self.input_hash.encode(), self.length, domains[i].encode(), domains[i+1].encode())
        self.sock.sendto(message, server)
        logging.info("Sent request: %s,to %s", message, server)
        i += 1


def get_offers(self):
    while True:
        try:
            logging.info("waiting for offers...")
            (data, addr) = self.sock.recvfrom(BUFFER_SIZE)
            if data:
                logging.info("Got an offer! Server: %s. data: %s", addr, data.decode())
                self.servers.add(addr)
        except timeout:
            if not self.servers:
                logging.info("No body wants to get handle my requests, no offers timeout!")
            else:
                logging.info("received: %d offers", len(self.servers))
            break


def discover_self(self):
    discover_message = pack(DISCOVER_FORMAT, HASHED_TEAM_NAME.encode(), DISCOVER)
    set_broadcast_mode(self)
    self.sock.sendto(discover_message, ('<broadcast>', 3117))
    logging.info("Sent broadcast discover message to port 3117")
    get_offers(self)


def set_broadcast_mode(self):
    self.sock.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
    self.sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)  # Enable broadcasting mode


def init_connection(self):
    self.sock = socket(AF_INET, SOCK_DGRAM)
    self.sock.bind(self.address)
    self.sock.settimeout(OFFER_TIMEOUT)


def create_message_struct(team_name, op_code, hashed_str, length, from_, to_, self):
    return self.MESSAGE_STRUCT.pack(team_name.encode(), op_code, hashed_str.encode(), length, from_.encode(), to_.encode())


class Client:
    def __init__(self):
        self.input_hash = ""
        self.length = 0
        self.sock = 0
        self.UDP_PORT = 3117
        self.FORMAT = 0
        self.UDP_IP = "192.168.43.13"
        self.address = (self.UDP_IP, self.UDP_PORT)
        self.servers = set()

    def run(self):
        try:
            welcome_user_and_get_hash(self)
            get_input_hash_and_length(self)
            init_connection(self)
            ask_hash_solution(self)
        except:
            print("you can't kill me")
            main()


def main():
    client = Client()
    client.run()


if __name__ == "__main__":
    format = "%(asctime)s: %(message)s"
    logging.basicConfig(format=format, level=logging.INFO,
                        datefmt="%H:%M:%S")
    main()
