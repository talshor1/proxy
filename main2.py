import threading
import socket
import ssl
from cryptography import x509
import OpenSSL

BUFFER_SIZE = 256
HOST = '127.0.0.1'
PORT = 443


def get_relevant_data(buffer):
    """
    :param buffer: The data we recieved from the client in bytes format.
    :return: The host name and port of the end point. (and printing the data information)
    """
    print('Parsing the request...')
    try:
        buffer_str = buffer.decode('utf8').replace("'", '"')
        request_arr = buffer_str.split('\r\n')
        first_line = request_arr[0]
        host_end = first_line.find(':')
        host_start = first_line.find(' ')
        host_name = first_line[host_start + 1:host_end]
        port = first_line[host_end + 1:host_end + 4]
        print('Buddy information:')
        for line in request_arr:
            print(line)
        print('==================')
        return host_name, int(port)
    except Exception as e:
        print(str(e))
        return None


def check_site_ip(host):
    """
    :param host: Site name which we want to check the ip if its not stackoverflow.
    :return: True if the site ip should be blocked.
    """
    print('Checking the ip of the site... {}'.format(host))
    blocked_ip = socket.gethostbyname('stackoverflow.com')
    curr_ip = socket.gethostbyname(host)
    if curr_ip == blocked_ip:
        return True
    return False


def exit_all(client, conn):
    if client:
        try:
            client.close()
        except Exception as e:
            print('Client is already closed...{}'.format(str(e)))
    if conn:
        try:
            conn.close()
        except Exception as e:
            print('server is already closed...{}'.format(str(e)))


def get_stackoverflow_certificate():
    return ssl.get_server_certificate(('www.stackoverflow.com', 443), ssl.PROTOCOL_TLSv1_2)


def handle_client(client, address):
    print('Welcome {}-{}'.format(address[0], address[1]))
    buffer = b''
    while True:
        data = client.recv(BUFFER_SIZE)
        buffer += data
        if len(data) < BUFFER_SIZE and len(buffer) > 0:
            break

    host, port = get_relevant_data(buffer)

    print("Requested host:--{}--, requested port:--{}--".format(host, port))
    if check_site_ip(host):
        print('Cant move on...not a legal ip!!')
        client.close()
        return

    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.verify_mode = ssl.CERT_NONE
    conn = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host)

    try:
        host_cert = ssl.get_server_certificate((host, port), ssl.PROTOCOL_TLSv1_2)
        if host_cert == get_stackoverflow_certificate():
            print('Oh no, cant move on...')
            exit_all(client, None)
            return

        print('Trying to connect to the server and move on the data')
        conn.connect((host, port))
        conn.sendall(buffer)
        while True:
            buffer = conn.recv(BUFFER_SIZE)
            if len(buffer) > 0:
                break
        print('Got response from the server: {}'.format(buffer))
        client.send(buffer)
    except Exception as e:
        print('Cant connect... {}'.format(str(e)))
    finally:
        exit_all(client, conn)


def main():
    print('Starting server....')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(3)
    while True:
        client, address = sock.accept()
        new_client_thread = threading.Thread(target=handle_client, args=(client, address))
        new_client_thread.setDaemon(True)
        new_client_thread.start()


if __name__ == "__main__":
    main()

