from socket import *
import hashlib
import logging
import threading
import time
from struct import *

UTF8 = 'utf-8'
TEAM_NAMES = []
TEAM_NAME_LENGTH = 32
HASHED_MSG_LENGTH = 40
BUFFER = 1024
OFFER = 2
ACK = 4
NACK = 5
WAITING_SEC = 10
THREAD_COUNTER = 0
TEAM_NAME = "Avner"
MESSAGE_STRUCT = Struct("32s B 40s B 256s 256s")
MESSAGE_STRUCT_WITH_LEN = Struct("32s B 40s B")
MESSAGE_STRUCT_WITH_LEN_BYTES = 74
MESSAGE_REQUEST_DYNAMIC_FORMAT = '32s B 40s B {0}s {0}s'
MESSAGE_STRUCT_START = Struct("32s B")
UDP_ADDR_TUPLE = ("", 3117)
SOCK = socket(AF_INET, SOCK_DGRAM)
SOCK.bind(UDP_ADDR_TUPLE)


def increase_char(c):
    i = ord(c[0])
    i += 1
    return chr(i)


def increase_from(from_):
    if len(from_) == 0:
        return ""
    last_char_i = len(from_) - 1
    if from_[last_char_i] == 'z':
        return increase_from(from_[:last_char_i]) + 'a'
    return from_[:last_char_i] + increase_char(from_[last_char_i])


def hash_matches(expcd_res, from_, name):
    result = hashlib.sha1(from_.encode(UTF8)).hexdigest()
    if result == expcd_res:
        logging.info("Thread %s: found match: %s", name, from_)
        return True
    return False


def search(from_, to_, expcd_res, name):
    start_time = time.time()
    while from_ != to_ and time.time() - start_time < WAITING_SEC:
        if hash_matches(expcd_res, from_, name):
            return True, from_
        from_ = increase_from(from_)
        if from_ == to_ and hash_matches(expcd_res, from_, name):
            return True, from_
    logging.info("Thread %s: couldn't find match: %s", name, expcd_res)
    return False, ""


def verify_request_input(hashed_str, length, from_, to_, name):
    logging.info("Thread %s: expected result: %s", name, hashed_str)

    if length < 1:
        return False

    from_ = from_[:length]
    to_ = to_[:length]

    if (not from_.isalpha()) or (not to_.isalpha()):
        logging.error("Thread %s: not alphabetic input. from: %s, to: %s. length: %d", name, from_, to_, length)
        return False, "", ""

    if len(from_) != length or len(to_) != length:
        logging.error("Thread %s: length does not match", name)
        return False, "", ""

    return True, from_, to_


def create_response_msg(result, response_msg, hashed_msg, length):
    if len(result) == 0:
        return pack('32s B 40s B', TEAM_NAME.encode(), response_msg, hashed_msg.encode(), length)
    else:
        req_format = '32s B 40s B {0}s'.format(length)
        return pack(req_format, TEAM_NAME.encode(), response_msg, hashed_msg.encode(), length, result.encode())


def run_new_thread(name, team_name, expcd_res, length, from_, to_, addr):
    is_legal, from_, to_ = verify_request_input(expcd_res, length, from_, to_, name)
    if is_legal:
        logging.info("Thread %s: searching from: %s, to: %s. length: %d", name, from_, to_, length)
        is_found, result = search(from_, to_, expcd_res, name)
        if is_found:
            send(name, create_response_msg(result, ACK, expcd_res, length), addr, team_name)
        else:
            send(name, create_response_msg("", NACK, expcd_res, length), addr, team_name)
    else:
        logging.error("Thread %s: illegal input.", name)


def request(team_name, hashed_str, length, from_, to_, name, addr):
    global TEAM_NAMES
    global THREAD_COUNTER
    if team_name in TEAM_NAMES:
        logging.info("Thread %s: removing team name: %s", name, team_name)
        TEAM_NAMES.remove(team_name)
        THREAD_COUNTER = THREAD_COUNTER + 1
        thread_name = "Thread" + str(THREAD_COUNTER)
        new_thread = threading.Thread(target=run_new_thread, args=(thread_name, team_name, hashed_str.decode(), length,
                                                                   from_.decode(UTF8), to_.decode(UTF8), addr,))
        logging.info("Thread %s: running new thread", name)
        new_thread.start()
    else:
        logging.error("Thread %s: unknown team name %s", name, team_name)
    return ""


def discover(name, team_name):
    TEAM_NAMES.append(team_name)
    logging.info("Thread %s: adding '%s' to names list", name, team_name)
    return MESSAGE_STRUCT.pack(team_name.encode(), OFFER, "N/A".encode(), 1, "N/A".encode(), "N/A".encode())


def try_discover(name, message):
    try:
        team_name, opcode = MESSAGE_STRUCT_START.unpack(message)
        team_name = team_name.decode()
        if opcode == 1:
            return False, discover(name, team_name), team_name
        else:
            logging.error("Thread %s: try_discover: failed parsing message type: %d", name, opcode)
            return False, "", ""
    except error:
        return True, "", ""


def try_request(message, name, addr):
    try:
        team_name, opcode, hashed_str, length = MESSAGE_STRUCT_WITH_LEN.unpack(message[:MESSAGE_STRUCT_WITH_LEN_BYTES])
        req_format = MESSAGE_REQUEST_DYNAMIC_FORMAT.format(length)
        team_name, opcode, hashed_str, length, from_, to_ = unpack(req_format, message)
        if opcode == 3:
            return request(team_name.decode(UTF8), hashed_str, length, from_, to_, name, addr), team_name
        else:
            logging.error("Thread %s: try_request: failed parsing message type: %d", name, opcode)
            return "", ""
    except error:
        logging.error("Thread %s: try_request: failed parsing message! EXCEPTION: %s", name, error)
        return "", ""


def parse_message(message, name, addr):
    logging.info("Thread %s: parsing message: %s", name, message)
    if len(message) < TEAM_NAME_LENGTH + 1:
        logging.error("Thread %s: failed parsing message: %s", name, message)
        return "", ""
    failed_discover, result, team_name = try_discover(name, message)
    if not failed_discover:
        return result, team_name
    else:
        return try_request(message, name, addr)


def send(name, result, addr, team_name):
    global SOCK
    logging.info("Thread %s: sending message: %s, to team: %s", name, result, team_name)
    SOCK.sendto(result, addr)


def receive(name):
    global SOCK
    global TEAM_NAME_LENGTH
    global BUFFER
    global UDP_ADDR_TUPLE

    logging.info("Thread %s: running server...", name)
    while True:
        logging.info("Thread %s: receiving...", name)
        (data, addr) = SOCK.recvfrom(BUFFER)  # buffer size is 1024 bytes
        logging.info("Thread %s: received data: %s, from: %s", name, data, addr)
        try:
            result, team_name = parse_message(data, name, addr)
            if len(result) != 0:
                send(name, result, addr, team_name)
        except:
            logging.error("something weird occurred. :(")


if __name__ == "__main__":
    format_ = "[%(levelname)8s]: %(asctime)s: %(message)s"
    logging.basicConfig(format=format_, level=logging.INFO,
                        datefmt="%H:%M:%S")
    while True:
        receive("Main")
