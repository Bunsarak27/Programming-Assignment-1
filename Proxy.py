# Include the libraries for socket and system calls
import socket
import sys
import os
import argparse
import re
import time

# 1MB buffer size
BUFFER_SIZE = 1000000

# Get the IP address and Port number to use for this web proxy server
parser = argparse.ArgumentParser()
parser.add_argument('hostname', nargs='?', default='127.0.0.1', help='IP address of the proxy server')
parser.add_argument('port', nargs='?', default=8888, help='Port number of the proxy server')
args = parser.parse_args()
proxyHost = args.hostname
proxyPort = int(args.port)

# Ensure the cache directory exists
if not os.path.exists('./cache'):
    os.makedirs('./cache')

# Create a server socket, bind it to a port and start listening
try:
    # ~~~~ INSERT CODE ~~~~
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ~~~~ END CODE INSERT ~~~~
    print('Created socket')
except:
    print('Failed to create socket')
    sys.exit()

try:
    # ~~~~ INSERT CODE ~~~~
    serverSocket.bind((proxyHost, proxyPort))
    # ~~~~ END CODE INSERT ~~~~
    print('Port is bound')
except:
    print('Port is already in use')
    sys.exit()

try:
    # ~~~~ INSERT CODE ~~~~
    serverSocket.listen(5)
    # ~~~~ END CODE INSERT ~~~~
    print('Listening to socket')
except:
    print('Failed to listen')
    sys.exit()

# continuously accept connections
while True:
    print('Waiting for connection...')
    clientSocket = None

    # Accept connection from client and store in the clientSocket
    try:
        # ~~~~ INSERT CODE ~~~~
        clientSocket, addr = serverSocket.accept()
        # ~~~~ END CODE INSERT ~~~~
        print('Received a connection')
    except:
        print('Failed to accept connection')
        sys.exit()

    # Get HTTP request from client
    # and store it in the variable: message_bytes
    try:
        # ~~~~ INSERT CODE ~~~~
        message_bytes = clientSocket.recv(BUFFER_SIZE)
        # ~~~~ END CODE INSERT ~~~~
        message = message_bytes.decode('utf-8', errors='ignore')
        print('Received request:')
        print('< ' + message)
    except:
        print('Error receiving request')
        clientSocket.close()
        continue

    requestParts = message.split()
    if len(requestParts) < 3:
        print("Malformed request")
        clientSocket.close()
        continue

    # Extract the method, URI and version of the HTTP client request 
    method = requestParts[0]
    URI = requestParts[1]
    version = requestParts[2]

    print('Method:\t\t' + method)
    print('URI:\t\t' + URI)
    print('Version:\t' + version)
    print('')

    # Get the requested resource from URI
    # Remove http protocol from the URI
    URI = re.sub('^(/?)http(s?)://', '', URI, count=1)

    # Remove parent directory changes - security
    URI = URI.replace('/..', '')

    # Split hostname from resource name
    resourceParts = URI.split('/', 1)
    hostname = resourceParts[0]
    resource = '/'
    if len(resourceParts) == 2:
        # Resource is absolute URI with hostname and resource
        resource = '/' + resourceParts[1]

    print('Requested Resource:\t' + resource)

    # Check if resource is in cache
    try:
        cacheLocation = './cache/' + hostname + resource
        if cacheLocation.endswith('/'):
            cacheLocation += 'default'

        print('Cache location:\t\t' + cacheLocation)

        fileExists = os.path.isfile(cacheLocation)

        if fileExists:
            file_age = int(os.path.getmtime(cacheLocation))
            current_time = int(time.time())
            age_seconds = current_time - file_age

            meta_path = cacheLocation + ".meta"
            if os.path.exists(meta_path):
                with open(meta_path, 'r') as meta:
                    meta_data = meta.read()
                    if "max-age=" in meta_data:
                        try:
                            max_age = int(meta_data.split("max-age=")[1].split(",")[0])
                            if age_seconds > max_age:
                                print(f"[CACHE] Expired (age: {age_seconds}s > max-age: {max_age}s)")
                                raise Exception("Cache expired")
                        except:
                            print("[CACHE] Failed to parse max-age, fallback to origin fetch")

            print('Cache hit! Loading from cache file: ' + cacheLocation)
            with open(cacheLocation, 'rb') as cacheFile:
                cacheData = cacheFile.read()
                # ProxyServer finds a cache hit
                # Send back response to client 
                # ~~~~ INSERT CODE ~~~~
                clientSocket.sendall(cacheData)
                # ~~~~ END CODE INSERT ~~~~
            print('Sent cached response to the client.')
            clientSocket.close()
            continue

        # cache miss.  Get resource from origin server
        originServerSocket = None
        # Create a socket to connect to origin server
        # and store in originServerSocket
        # ~~~~ INSERT CODE ~~~~
        originServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # ~~~~ END CODE INSERT ~~~~

        print('Connecting to:\t\t' + hostname + '\n')
        try:
            # Get the IP address for a hostname
            address = socket.gethostbyname(hostname)
            # Connect to the origin server
            # ~~~~ INSERT CODE ~~~~
            originServerSocket.connect((address, 80))
            # ~~~~ END CODE INSERT ~~~~
            print('Connected to origin Server')

            originServerRequest = ''
            originServerRequestHeader = ''
            # Create origin server request line and headers to send
            # originServerRequest is the first line in the request and
            # originServerRequestHeader is the second line in the request
            # ~~~~ INSERT CODE ~~~~
            originServerRequest = f"GET {resource} HTTP/1.1"
            originServerRequestHeader = f"Host: {hostname}"
            # ~~~~ END CODE INSERT ~~~~

            # Construct the request to send to the origin server
            request = originServerRequest + '\r\n' + originServerRequestHeader + '\r\n\r\n'

            # Request the web resource from origin server
            print('Forwarding request to origin server:')
            for line in request.split('\r\n'):
                print('> ' + line)

            try:
                originServerSocket.sendall(request.encode())
            except socket.error:
                print('Forward request to origin failed')
                sys.exit()

            print('Request sent to origin server\n')

            # Get the response from the origin server
            # ~~~~ INSERT CODE ~~~~
            originResponse = b""
            while True:
                data = originServerSocket.recv(BUFFER_SIZE)
                if not data:
                    break
                originResponse += data
            # ~~~~ END CODE INSERT ~~~~

            # Check for HTTP redirect response
            status_line = originResponse.split(b'\r\n', 1)[0]
            if b'301' in status_line or b'302' in status_line:
                print('[REDIRECT] Detected 301/302 response')
                clientSocket.sendall(originResponse)
                print('[REDIRECT] Response forwarded to client (not cached)')
                originServerSocket.close()
                clientSocket.shutdown(socket.SHUT_WR)
                clientSocket.close()
                continue

            # Send the response to the client
            # ~~~~ INSERT CODE ~~~~
            clientSocket.sendall(originResponse)
            # ~~~~ END CODE INSERT ~~~~

            # Create a new file in the cache for the requested file.
            cacheDir, file = os.path.split(cacheLocation)
            if not os.path.exists(cacheDir):
                os.makedirs(cacheDir)

            with open(cacheLocation, 'wb') as cacheFile:
                # Save origin server response in the cache file
                # ~~~~ INSERT CODE ~~~~
                cacheFile.write(originResponse)
                # ~~~~ END CODE INSERT ~~~~

            # Handle Cache-Control header
            headers = originResponse.split(b'\r\n\r\n')[0].decode(errors='ignore')
            for line in headers.split('\r\n'):
                if line.lower().startswith("cache-control:"):
                    meta_path = cacheLocation + ".meta"
                    with open(meta_path, 'w') as meta_file:
                        meta_file.write(line)
                        print(f"[CACHE] Saved cache-control metadata: {line}")

            print('Response cached and sent to client.')
            originServerSocket.close()
            clientSocket.shutdown(socket.SHUT_WR)
        except OSError as err:
            print('origin server request failed. ' + err.strerror)

    except Exception as e:
        print(f'[ERROR] Failed to handle request: {e}')

    try:
        clientSocket.close()
    except:
        print('Failed to close client socket')
