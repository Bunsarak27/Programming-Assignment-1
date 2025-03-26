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
parser.add_argument('hostname', nargs='?', default='127.0.0.1', help='the IP Address Of Proxy Server')
parser.add_argument('port', nargs='?', default=8888, help='the port number of the proxy server')
args = parser.parse_args()
proxyHost = args.hostname
proxyPort = int(args.port)

# Create a server socket, bind it to a port and start listening
try:
  # ~~~~ INSERT CODE ~~~~
  serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  # ~~~~ END CODE INSERT ~~~~
  print ('Created socket')
except:
  print ('Failed to create socket')
  sys.exit()

try:
  # ~~~~ INSERT CODE ~~~~
  serverSocket.bind((proxyHost, proxyPort))
  # ~~~~ END CODE INSERT ~~~~
  print ('Port is bound')
except:
  print('Port is already in use')
  sys.exit()

try:
  # ~~~~ INSERT CODE ~~~~
  serverSocket.listen(5)
  # ~~~~ END CODE INSERT ~~~~
  print ('Listening to socket')
except:
  print ('Failed to listen')
  sys.exit()

# continuously accept connections
while True:
  print ('Waiting for connection...')
  clientSocket = None

  try:
    # ~~~~ INSERT CODE ~~~~
    clientSocket, addr = serverSocket.accept()
    # ~~~~ END CODE INSERT ~~~~
    print ('Received a connection')
  except:
    print ('Failed to accept connection')
    sys.exit()

  # ~~~~ INSERT CODE ~~~~
  message_bytes = clientSocket.recv(BUFFER_SIZE)
  # ~~~~ END CODE INSERT ~~~~
  message = message_bytes.decode('utf-8', errors='ignore')
  print ('Received request:')
  print ('< ' + message)

  requestParts = message.split()
  if len(requestParts) < 3:
    clientSocket.close()
    continue

  method = requestParts[0]
  URI = requestParts[1]
  version = requestParts[2]

  print ('Method:\t\t' + method)
  print ('URI:\t\t' + URI)
  print ('Version:\t' + version)
  print ('')

  URI = re.sub('^(/?)http(s?)://', '', URI, count=1)
  URI = URI.replace('/..', '')

  resourceParts = URI.split('/', 1)
  hostname = resourceParts[0]
  resource = '/'
  if len(resourceParts) == 2:
    resource = '/' + resourceParts[1]

  print ('Requested Resource:\t' + resource)

  try:
    cacheLocation = './cache/' + hostname + resource
    if cacheLocation.endswith('/'):
        cacheLocation += 'default'

    print ('Cache location:\t\t' + cacheLocation)

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
                raise Exception("Cache expired")
            except:
              pass

      print('Cache hit! Loading from cache file: ' + cacheLocation)
      # ~~~~ INSERT CODE ~~~~
      with open(cacheLocation, 'rb') as cacheFile:
        cacheData = cacheFile.read()
        clientSocket.sendall(cacheData)
      # ~~~~ END CODE INSERT ~~~~
      print ('Sent to the client (cached).')
      clientSocket.close()
      continue
  except:
    pass

  originServerSocket = None
  # ~~~~ INSERT CODE ~~~~
  originServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  # ~~~~ END CODE INSERT ~~~~

  print ('Connecting to:\t\t' + hostname + '\n')
  try:
    address = socket.gethostbyname(hostname)
    # ~~~~ INSERT CODE ~~~~
    originServerSocket.connect((address, 80))
    # ~~~~ END CODE INSERT ~~~~
    print ('Connected to origin Server')

    # ~~~~ INSERT CODE ~~~~
    originServerRequest = f"GET {resource} HTTP/1.1"
    originServerRequestHeader = f"Host: {hostname}"
    # ~~~~ END CODE INSERT ~~~~

    request = originServerRequest + '\r\n' + originServerRequestHeader + '\r\n\r\n'
    print ('Forwarding request to origin server:')
    for line in request.split('\r\n'):
      print ('> ' + line)

    try:
      originServerSocket.sendall(request.encode())
    except socket.error:
      print ('Forward request to origin failed')
      sys.exit()

    print('Request sent to origin server\n')

    # ~~~~ INSERT CODE ~~~~
    originResponse = b""
    while True:
      data = originServerSocket.recv(BUFFER_SIZE)
      if not data:
        break
      originResponse += data
    # ~~~~ END CODE INSERT ~~~~

    status_line = originResponse.split(b'\r\n', 1)[0]
    if b'301' in status_line or b'302' in status_line:
      print('[REDIRECT] Detected 301/302 response')
      clientSocket.sendall(originResponse)
      print('[REDIRECT] Response forwarded to client (not cached)')
      originServerSocket.close()
      clientSocket.shutdown(socket.SHUT_WR)
      clientSocket.close()
      continue

    # ~~~~ INSERT CODE ~~~~
    clientSocket.sendall(originResponse)
    # ~~~~ END CODE INSERT ~~~~

    cacheDir, file = os.path.split(cacheLocation)
    if not os.path.exists(cacheDir):
      os.makedirs(cacheDir)

    with open(cacheLocation, 'wb') as cacheFile:
      # ~~~~ INSERT CODE ~~~~
      cacheFile.write(originResponse)
      # ~~~~ END CODE INSERT ~~~~

    headers = originResponse.split(b'\r\n\r\n')[0].decode(errors='ignore')
    for line in headers.split('\r\n'):
      if line.lower().startswith("cache-control:"):
        meta_path = cacheLocation + ".meta"
        with open(meta_path, 'w') as meta_file:
          meta_file.write(line)

    print ('origin response received. Closing sockets')
    originServerSocket.close()
    clientSocket.shutdown(socket.SHUT_WR)
  except OSError as err:
    print ('origin server request failed. ' + err.strerror)

  try:
    clientSocket.close()
  except:
    print ('Failed to close client socket')
