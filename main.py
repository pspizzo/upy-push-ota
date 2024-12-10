import gc
import machine
import network
import socket
import time
import binascii
import uselect
import hashlib
import random
import sys
import os
import deflate
import tarfile
import cryptolib
import _thread # multicore support on RPi Pico

OTA_VERSION = '0.0.1'

# Used to randomly generate a temporary filename when uploading an OTA update
ascii_letters = list(map(chr, range(ord('a'), ord('z') + 1))) + list(map(chr, range(ord('0'), ord('9') + 1)))


# Read the configuration file. May cause a fatal error if critical configurations are missing,
# such as the WiFi settings.
try:
    import otaconfig
except Exception as e:
    print('Failed to load otaconfig')
    sys.print_exception(e)
    sys.exit(1)
if not otaconfig.wifi_ssid:
    print('No WiFi SSID, cannot initialize network')
    sys.exit(1)

# If the configuration contains a crypto_key, OTA requests are signed for security.
# RECOMMENDATION: set a crypto key. See the README for instructions.
# WARNING: Not using a crypto key will allow anyone to upload new code to your device.
crypto_key = None
if hasattr(otaconfig, 'crypto_key') and otaconfig.crypto_key:
    try:
        crypto_key = binascii.unhexlify(otaconfig.crypto_key)
        if len(crypto_key) != 16 and len(crypto_key) != 32:
            print(f'Invalid crypto key length: {len(crypto_key)} bytes')
            sys.exit(1)
    except Exeption as e:
        print('Failed to parse otaconfig.crypto_key')
        sys.print_exception(e)
        sys.exit(1)


# Convert string to long, ignoring errors
def safe_long(val, default_val = None, log_prefix = None):
    try:
        return long(val)
    except Exception:
        if log_prefix:
            print(f'{log_prefix}: {val}')
        return default_val

# Convert string to int, ignoring errors
def safe_int(val, default_val = None, log_prefix = None):
    return int(safe_long(val, default_val, log_prefix))


# Logger, includes network logging
is_wlan_connected = False
log_to_network_host = None
log_to_network_port = None
if hasattr(otaconfig, 'network_log_host'):
    log_to_network_host = otaconfig.network_log_host
if hasattr(otaconfig, 'network_log_port'):
    log_to_network_port = safe_int(otaconfig.network_log_port, log_prefix='Invalid network_log_port')
if log_to_network_host and log_to_network_port:
    print(f'Network logging enabled to {log_to_network_host}:{log_to_network_port}')

log_level = 20
if hasattr(otaconfig, 'log_level'):
    log_level = safe_int(otaconfig.log_level, 'Invalid log_level in otaconfig')

log_sock = None
def log_all(level, message):
    global log_level, log_sock, is_wlan_connected, log_to_network_host, log_to_network_port
    if level < log_level:
        return
    print(message)
    if is_wlan_connected and log_to_network_host and log_to_network_port:
        try:
            if not log_sock:
                log_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            log_sock.sendto(bytes(message + "\n", 'utf-8'), (log_to_network_host, log_to_network_port))
        except Exception as e:
            print(f'Failed to send network log: {e}')
            

def log_debug(message):
    log_all(10, message)
def log_info(message):
    log_all(20, message)
def log_warn(message):
    log_all(30, message)
def log_error(message):
    log_all(40, message)

# Initialize the run script. Protect against failures in the script.
try:
    import run
except Exception as e:
    log_error('Failed to load run.py')
    sys.print_exception(e)
    run = None
# If the script has an "initialize" method, run it now (protecting against failures).
# If the initialize method exists but throws an Exception, the run() loop will be skipped
# further down in the script. This is to prevent a run() call from failing due to bad init.
run_init_failure = False
if run and hasattr(run, 'initialize'):
    try:
        run.initialize()
    except Exception as e:
        log_error('run.initialize() failed')
        run_init_failure = True
        sys.print_exception(e)


# Initialize WiFi
wlan = network.WLAN(network.STA_IF)
wlan.active(True)
wlan.connect(otaconfig.wifi_ssid, otaconfig.wifi_passphrase)

# Logic for deferring WiFi / socket setup.
# Allows the main code to run even if the network is down.
def check_wifi_status():
    global is_wlan_connected
    if is_wlan_connected:
        return True
    if wlan.status() != network.STAT_GOT_IP:
        return False
    
    # First time we detected a valid connection, so print a status message
    mac_addr = wlan.config('mac')
    mac_addr_str = b''
    for i in range(len(mac_addr)):
        if i > 0:
            mac_addr_str += b':'
        mac_addr_str += binascii.hexlify(mac_addr[i:i+1])
    is_wlan_connected = True
    log_info(f'WLAN mac: {mac_addr_str.decode()}, ip: {wlan.ifconfig()[0]}')

# Logic for deferring socket setup.
# Allows the main code to run even if the network is down.
server_socket = None
def setup_server():
    global server_socket
    if server_socket:
        return True
    if not check_wifi_status():
        return False
    addr = socket.getaddrinfo('0.0.0.0', 2365)[0][-1]
    server_socket = socket.socket()
    server_socket.bind(addr)
    server_socket.listen(1)
    log_info(f'Listening on TCP-{addr[1]}')
    return True


# Main HTTP handler logic. Allows easily passing request information and the socket to run.py.
class HttpHandler:
    socket = None
    method = None # GET, POST, etc.
    path = None   # The full path URL, including query parameters
    headers = dict()
    initial_data = b''
    
    # On init, get the request method, path, headers, etc.
    def __init__(self, soc):
        self.socket = soc

        data = self.socket.recv(1024)
        log_info(f'Data received: {len(data)}')
        
        # Example first line: POST /ota/update HTTP/1.1\r\n
        first_line_end = data.find(b'\r\n')
        if first_line_end < 0:
            raise Exception('No newline while finding method+path')
        
        # Get the method and path from the first line
        first_space = data.find(b' ', 3, first_line_end)
        if first_space < 0:
            raise Exception('Invalid HTTP request, no space in first line')
        self.method = data[0:first_space].decode()
        path_end = data.find(b' HTTP/1', first_space, first_line_end)
        if path_end < 0:
            raise Exception('Invalid HTTP request, cannot find path')
        self.path = data[first_space + 1 : path_end].decode()
        
        # All lines before two newlines are headers -- parse them into self.headers
        headers_end = data.find(b'\r\n\r\n', first_line_end + 2)
        if headers_end < 0:
            raise Exception('Cannot find HTTP headers')
        i = first_line_end + 2
        while i < headers_end:
            eol = data.find(b'\r\n', i)
            if eol > 0:
                name_end = data.find(b':', i, eol)
                if name_end > 0:
                    name = data[i : name_end].decode().lower()
                    value = data[name_end + 1 : eol].decode().strip()
                    self.headers[name] = value
                i = eol + 2
            else:
                i = len(data)

        # If any data remains, store it in the self.initial_data bytestring.
        if len(data) > (headers_end + 2):
            self.initial_data = data[headers_end + 4:]

    # Get a header from the request. Returns None if not found. Returns a string value.
    def header(self, name):
        if name not in self.headers:
            return None
        return self.headers[name]

    # Respond with the text message
    def send_text(self, http_code, http_message, text_message):
        self.socket.send(f'HTTP/1.0 {http_code} {http_message}\r\nContent-type: text/text\r\n\r\n{text_message}\r\n')

    # Respond with a generic "OK" response
    def send_text_ok(self, text_message = None):
        m = 'OK'
        if text_message:
            m = text_message
        self.send_text(200, 'OK', m)
    
    # Respond with a generic "NOT FOUND" response
    def send_text_not_found(self):
        self.send_text(404, 'NOT FOUND', 'Not found')

    # Close the connection
    def close(self):
        self.socket.close()


def is_protected_file(filename):
    return filename == 'main.py' or filename == 'otaconfig.py' or filename.startswith('tarfile/')


# After we received an OTA update, this function unpacks the files to the local system.
def unpack_files(filename):
    try:
        with open(filename, 'rb') as fin:
            din = deflate.DeflateIO(fin, deflate.GZIP)
            tin = tarfile.TarFile(fileobj=din)
            for finfo in tin:
                name = finfo.name
                if name.endswith('/'):
                    # Directory
                    try:
                        os.mkdir(name[:-1])
                        log_debug(f'Created directory {name}')
                    except OSError as e:
                        if e.errno == 17:
                            pass # Already exists
                        else:
                            raise e
                    continue
                data = tin.extractfile(finfo)
                with open(name, 'wb') as data_out:
                    written = 0
                    while True:
                        buf = data.read(512)
                        if not buf:
                            break
                        written += data_out.write(buf)
                    log_debug(f'File {name} ({written} bytes) written')
        return None
    except Exception as e:
        return 'Unpack error'


def compare_signature(enc_sig, expected_content):
    sig_bytes = binascii.a2b_base64(enc_sig) # base64-decode
    aes_ecb = cryptolib.aes(crypto_key, 1) # MODE_ECB
    decoded_sig = aes_ecb.decrypt(sig_bytes).decode()
    if decoded_sig and len(decoded_sig) > 0 and ord(decoded_sig[-1]) < 32:
        # Strip non-ASCII padding characters from the end
        decoded_sig = decoded_sig.rstrip(decoded_sig[-1])
    if decoded_sig != expected_content:
        log_debug(f'Decoded sig: {decoded_sig} {ord(decoded_sig[-1])}')
        return False
    return True


# Check authentication of the HTTP request.
#    handler: the HttpHandler instance for this connection
#    content: if True, contents are expected with the connection, so use content hashing with signatures.
#             If contents are not found, the request is denied.

# TODO ---- SECURITY IMPROVEMENT
#   - Add another field, 'sig-time' -- ms since epoch
#     + Include sig-time in the hash (for all requests)
#     + Track the "last sig-time" value -- the new sig-time MUST be > old-sig-time
#     + Possible problem: setting an incorrect high ota-time will DOS the device
last_ota_time = 0
def authenticate(handler, content=False):
    global last_ota_time

    if not crypto_key:
        # Authentication is not configured
        return True
    rcvd_sig = handler.header('ota-sig')
    if not rcvd_sig:
        handler.send_text(401, 'FORBIDDEN', 'Missing signature')
        return False
    # rcvd_time = safe_long(handler.header('ota-time'))
    # if not rcvd_time or rcvd_time <= last_ota_time:
    #     handler.send_text(401, 'FORBIDDEN', 'Invalid ota-time')
    #     return False

    simple_auth = False
    if not content and handler.method == 'GET':
        simple_auth = True
    clength_str = handler.header('content-length')
    if not content and not clength_str:
        simple_auth = True
    if simple_auth:
        # No content in this request, so compare the signature against the time/method/URL
        try:
            if not compare_signature(rcvd_sig, f'{handler.method}.{handler.path}'):
                handler.send_text(401, 'FORBIDDEN', 'Invalid signature')
                return False
        except Exception as e:
            sys.print_exception(e)
            handler.send_text(500, 'INTERNAL SERVER ERROR', 'Failed to verify signature')
            return False
        return True

    # Compare the signature against the content hash/content length
    rcvd_hash = handler.header('ota-hash')
    if not rcvd_hash:
        handler.send_text(400, 'BAD REQUEST', 'Missing hash')
        return False
    if not clength_str:
        handler.send_text(400, 'BAD REQUEST', 'Missing content length')
        return False
    try:
        content_length = int(clength_str)
    except Exception:
        handler.send_text(400, 'BAD REQUEST', f'Bad content length: {clength_str}')
        return False
    try:
        if not compare_signature(rcvd_sig, f'{rcvd_hash}.{content_length}'):
            handler.send_text(401, 'FORBIDDEN', 'Invalid signature')
            return False
    except Exception as e:
        sys.print_exception(e)
        handler.send_text(500, 'INTERNAL SERVER ERROR', 'Failed to calculate signature')
        return False


def has_enough_free_space(size_bytes):
    fs_stat = os.statvfs('/')
    free_bytes = fs_stat[0] * fs_stat[3] # block_size * free_blocks
    return free_bytes >= size_bytes


# Receives the OTA file from the HTTP client.
# Performs hash checking and signature checking, comparing against the provided HTTP headers.
def receive_new_file(handler):
    if not authenticate(handler, content=True):
        return False
    gc.collect()

    rcvd_hash = handler.header('ota-hash')
    clength_str = handler.header('content-length')
    try:
        content_length = int(clength_str)
    except Exception:
        handler.send_text(400, 'BAD REQUEST', f'Bad content length: {clength_str}')
        return False
    if not has_enough_free_space(content_length):
        handler.send_text(400, 'BAD REQUEST', 'Insufficient free space')
        return False

    random_filename = ''.join(map(lambda x:random.choice(ascii_letters), range(0, 16))) + '.tmp'
    hasher = hashlib.sha256()
    try:
        log_debug(f'Writing temp file: {random_filename}')
        with open(random_filename, 'wb') as fout:
            fout.write(handler.initial_data)
            hasher.update(handler.initial_data)
            i = len(handler.initial_data)
            while i < content_length:
                chunk_size = content_length - i
                if chunk_size > 1024:
                    chunk_size = 1024
                chunk = handler.socket.recv(chunk_size)
                if not chunk:
                    handler.send_text(400, 'BAD REQUEST', f'Mismatched content length, expected {content_length}, received {i}')
                    return False
                fout.write(chunk)
                hasher.update(chunk)
                i += len(chunk)

        calc_hash = binascii.hexlify(hasher.digest()).decode()
        log_debug(f'Received {i} bytes, hash {calc_hash}')
        if calc_hash != rcvd_hash:
            handler.send_text(400, 'BAD REQUEST', 'Mismatched hash')
            return False

        # TODO Additional options: protect safe files unless specific header is set
        unpack_err = unpack_files(random_filename)
        if unpack_err:
            handler.send_text(400, 'BAD REQUEST', f'Failed to unpack file contents: {unpack_err}')
            return False
        
        handler.send_text(200, 'OK', 'OK')
        return True
                
    except Exception as e:
        sys.print_exception(e)
        handler.send_text(500, 'INTERNAL SERVER ERROR', 'Failed to receive file')
        return False
    finally:
        try:
            os.remove(random_filename)
        except Exception:
            pass

def pair_values(*args):
    result = ''
    for i in range(0, len(args), 2):
        if (i + 1) < len(args):
            if result:
                result += '\n'
            result += f'{args[i]}={args[i+1]}'
    return result

# Handle an incoming network (HTTP) request
def handle_request(client, client_timeout_secs):
    global log_level, log_to_network_host, log_to_network_port, OTA_VERSION

    client.settimeout(client_timeout_secs)
    try:
        handler = HttpHandler(client)
        if handler.method == 'GET':
            if handler.path == '/ota/status':
                if authenticate(handler):
                    message = 'OK\n' + pair_values(
                        'ota_version', OTA_VERSION,
                        'log_level', log_level,
                        'log_host', log_to_network_host,
                        'log_port', log_to_network_port)
                    if hasattr(otaconfig, 'name') and otaconfig.name != '':
                        message = message + "\nname=" + otaconfig.name
                    # TODO Ability to include status from the run module?
                    handler.send_text_ok(message)
                return
        elif handler.method == 'POST':
            if handler.path == '/ota/update':
                needsReset = receive_new_file(handler)
                if needsReset:
                    client.close()
                    time.sleep_ms(500)
                    machine.reset()
                return
        elif handler.method == 'PUT':
            if handler.path.startswith('/ota/'):
                if not authenticate(handler):
                    return
                if handler.path.startswith('/ota/debug/host/'):
                    pathval = handler.path[16:]
                    log_to_network_host = pathval
                    handler.send_text_ok()
                    return
                if handler.path.startswith('/ota/debug/port/'):
                    pathval = handler.path[16:]
                    try:
                        log_to_network_port = int(pathval)
                        handler.send_text_ok()
                    except Exception:
                        handler.send_text(400, 'BAD REQUEST', f'Invalid port: "{pathval}"')
                    return
                if handler.path.startswith('/ota/debug/level/'):
                    pathval = handler.path[17:]
                    try:
                        log_level = int(pathval)
                        handler.send_text_ok()
                    except Exception as e:
                        handler.send_text(400, 'BAD REQUEST', f'Invalid log level: "{pathval}"')
                    return
        elif handler.method == 'DELETE':
            if handler.path.startswith('/ota/'):
                if not authenticate(handler):
                    return
                if handler.path.startswith('/ota/files/'):
                    fname = handler.path[11:]
                    if is_protected_file(fname):
                        handler.send_text(400, 'BAD REQUEST', 'Protected file')
                        return
                    try:
                        os.remove(fname)
                        log_info(f'Deleted file: {fname}')
                        handler.send_text_ok()
                    except Exception as e:
                        handler.send_text(500, 'INTERNAL SERVER ERROR', f'Failed to delete file: {e}')
                    return
                if handler.path == '/ota/debug/host':
                    log_to_network_host = None
                    handler.send_text_ok()
                    return
                if handler.path == '/ota/debug/port':
                    log_to_network_port = None
                    handler.send_text_ok()
                    return
        # TODO Handle custom API calls defined in the run module
        # TODO Allow (optional) handling authentication for custom API calls defined in the run module
        handler.send_text_not_found()
    except OSError as e:
        log_warn(f'Exception reading from client: {e}')
    finally:
        client.close()


def network_task_async():
    global server_socket
    socket_poller = None
    
    loop_period_secs = 3
    run_period_secs = 60
    client_socket_timeout = 10
    if hasattr(otaconfig, 'loop_period_secs'):
        loop_period_secs = otaconfig.loop_period_secs
    if hasattr(otaconfig, 'run_period_secs'):
        run_period_secs = otaconfig.run_period_secs
    if hasattr(otaconfig, 'client_socket_timeout'):
        client_socket_timeout = otaconfig.client_socket_timeout
    loop_period_ms = int(loop_period_secs * 1000)
    run_period_ms = int(run_period_secs * 1000)
    log_info(f'Initializing async network task, loop={loop_period_ms}ms, run={run_period_ms}ms')
    last_loop = None
    last_run = None
    
    while True:
        now = time.ticks_ms()
        if not last_loop or (now - last_loop) > loop_period_ms:
            last_loop = now
            if not socket_poller and setup_server():
                socket_poller = uselect.poll()
                socket_poller.register(server_socket, uselect.POLLIN)
            if socket_poller:
                # Check for incoming requests
                found = socket_poller.poll(1)
                if len(found) > 0:
                    log_debug('Accepting connection')
                    client, addr = server_socket.accept()
                    log_info(f'Client connected from: {addr}')
                    handle_request(client, client_socket_timeout)

        now = time.ticks_ms()
        if not last_run or (now - last_run) > run_period_ms:
            last_run = now
            if not run_init_failure and run and hasattr(run, 'loop'):
                try:
                    run.loop()
                except Exception as e:
                    log_error('run.loop() failed')
                    sys.print_exception(e)

        # How long should we run? We want to wake up the next time the loop or run script
        # needs to execute, so pick the sooner of the two.
        now = time.ticks_ms()
        sleep_to_next_loop = loop_period_ms
        if last_loop:
            sleep_to_next_loop -= (now - last_loop)
        sleep_to_next_run = run_period_ms
        if last_run:
            sleep_to_next_run -= (now - last_run)
        if sleep_to_next_loop > 0 and sleep_to_next_run > 0:
            to_sleep_ms = sleep_to_next_loop
            if sleep_to_next_run < to_sleep_ms:
                to_sleep_ms = sleep_to_next_run
            time.sleep_ms(to_sleep_ms)


if run and hasattr(run, 'main') and hasattr(otaconfig, 'multithread') and otaconfig.multithread and hasattr(run, 'main'):
    log_debug('Launching OTA thread on second core')
    _thread.start_new_thread(network_task_async, [])
    try:
        run.main()
    except Exception as e:
        log_error('run.main() failed')
        sys.print_exception(e)
else:
    network_task_async()
