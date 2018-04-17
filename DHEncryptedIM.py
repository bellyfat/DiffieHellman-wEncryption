#!/usr/bin/python

#Author : Henry Tan
#For COSC235
#Solution for HW1 - Part 1

import os
import sys
import argparse
import socket
import select
import logging
import signal #To kill the programs nicely
import random

from collections import deque
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
from Crypto.Cipher import AES

from collections import deque

############
#GLOBAL VARS
DEFAULT_PORT = 9999
s = None
server_s = None
logger = logging.getLogger('main')
###########


def parse_arguments():
  parser = argparse.ArgumentParser(description = 'A P2P IM service.')
  parser.add_argument('-c', dest='connect', metavar='HOSTNAME', type=str,
    help = 'Host to connect to')
  parser.add_argument('-s', dest='server', action='store_true',
    help = 'Run as server (on port 9999)')
  #parser.add_argument('-confkey', dest='confkey', metavar='CONFIDENTIALITY KEY', type=str,
    #help = 'Key used in encryption')
  #parser.add_argument('-authkey', dest='authkey', metavar='AUTHENTICITY KEY', type=str,
    #help = 'Key with which HMAC is computed')
  parser.add_argument('-p', dest='port', metavar='PORT', type=int, 
    default = DEFAULT_PORT,
    help = 'For testing purposes - allows use of different port')

  return parser.parse_args()

def print_how_to():
  print "This program must be run with exactly ONE of the following options"
  print "-c <HOSTNAME>  : to connect to <HOSTNAME> on tcp port 9999"
  print "-s             : to run a server listening on tcp port 9999"

def sigint_handler(signal, frame):
  logger.debug("SIGINT Captured! Killing")
  global s, server_s
  if s is not None:
    s.shutdown(socket.SHUT_RDWR)
    s.close()
  if server_s is not None:
    s.close()

  quit()

def init(crypt):
  global s
  args = parse_arguments()

  logging.basicConfig()
  logger.setLevel(logging.CRITICAL)
  
  #Catch the kill signal to close the socket gracefully
  signal.signal(signal.SIGINT, sigint_handler)

  if args.connect is None and args.server is False:
    print_how_to()
    quit()

  if args.connect is not None and args.server is not False:
    print_how_to()
    quit() 

  #we need to generate a confkey through diffie hellman
  sharedBase = 2    # g
  sharedHexPrime = ("00cc81ea8157352a9e9a318aac4e33"
              "ffba80fc8da3373fb44895109e4c3f"
              "f6cedcc55c02228fccbd551a504feb"
              "4346d2aef47053311ceaba95f6c540"
              "b967b9409e9f0502e598cfc71327c5"
              "a455e2e807bede1e0b7d23fbea054b"
              "951ca964eaecae7ba842ba1fc6818c"
              "453bf19eb9c5c86e723e69a210d4b7"
              "2561cab97b3fb3060b")      # p
  sharedPrime = int(sharedHexPrime, 16)

  

  #hash keys and take first 128 bits (=16 bytes)
  authkey="wedontcareabouthis"
  crypt['authout']=HMAC.new(authkey, digestmod=SHA256)
  crypt['authin']=HMAC.new(authkey, digestmod=SHA256)
  #args.confkey=SHA256.new(args.confkey).digest()[0:16]

  if args.connect is not None:
    iv=os.urandom(32)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logger.debug('Connecting to ' + args.connect + ' ' + str(args.port))
    s.connect((args.connect, args.port))
    s.send(iv)
    
    #lets generate alice secret
    aSecret = random.randint(1,16)
    #lets send alice public
    A = str(send_over_public(sharedBase, aSecret, sharedPrime))
    A = (-len(A)%5)*'0' + A
    s.send(A)
    #lets recieve bob public
    B = int(s.recv(5))
    #print(B)
    #calculate the private key
    secretA = str(compute_private(B, aSecret, sharedPrime))
    #print(secretA)
 
    #calculate AES
    confkey=SHA256.new(secretA).digest()[0:16]
    crypt['confout']=AES.new(confkey, AES.MODE_CBC, iv[:16])
    crypt['confin']=AES.new(confkey, AES.MODE_CBC, iv[16:])

  if args.server is not False:
    global server_s
    server_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_s.bind(('', args.port))
    server_s.listen(1) #Only one connection at a time
    s, remote_addr = server_s.accept()
    server_s.close()
    logger.debug("Connection received from " + str(remote_addr))
    iv=s.recv(32)

    #lets generate bob 
    bSecret = random.randint(1,16)
    #lets recieve alice public 
    A = int(s.recv(5))
    #lets send bob's public
    B = str(send_over_public(sharedBase, bSecret, sharedPrime))
    B = (-len(B)%5)*'0' + B
    s.send(B)
    #print(A)
    #calculate the privatekey
    secretB = str(compute_private(A, bSecret, sharedPrime))
    #print(secretB)
    
    #calculate AES
    confkey=SHA256.new(secretB).digest()[0:16]
    crypt['confout']=AES.new(confkey, AES.MODE_CBC, iv[16:])
    crypt['confin']=AES.new(confkey, AES.MODE_CBC, iv[:16])
    
    
    
def exp_by_squaring(x, n):
    if (n < 0):  
      return exp_by_squaring(1 / x, -n)
    elif(n == 0):
      return  1
    elif(n == 1):
      return  x 
    elif(n%2 == 0):
      return exp_by_squaring(x * x,  n / 2)
    elif(n%2 == 1):
      return x * exp_by_squaring(x * x, (n - 1) / 2)

def send_over_public(sharedbase, secret, sharedprime):
  return exp_by_squaring(sharedbase, secret) % sharedprime

def compute_private(publiclysent, secret, sharedprime):
  return exp_by_squaring(publiclysent, secret) % sharedprime    

def numto16bytestr(num):
  #converts int to 16-byte string with a bunch of 0s in front of it
  #obviously 16 bytes is unnecessarily large, but: simplicity.
  num = str(num)
  return (16-len(num))*'0' + num

def padstrto16bytes(data):
  #ensures string ends in newline, and pads to next multiple of 16 bytes
  #if str[-1] is not '\n':
  #  str += '\n'
  return data + (-len(data)%16)*'x'

def encodemessage(data,crypt):
  data = numto16bytestr(len(data))+padstrto16bytes(data)
  crypt['authout'].update(data)
  data = data + crypt['authout'].digest()[:32]
  data = crypt['confout'].encrypt(data)
  return data

def decodemessage(data,crypt):
  data = crypt['confin'].decrypt(data)
  mac = data[-32:]
  data = data[:-32]
  crypt['authin'].update(data)
  if mac != crypt['authin'].digest():
    exit("AUTH FAIL on: " + data)
  data = data[16:16+int(data[:16])]
  return data

def main():
  global s
  datalen=64
  
  crypt={}
  #crypt=['authout':None,'confout':None,'authin':None,'confin':None]

  init(crypt)
  
  inputs = [sys.stdin, s]
  outputs = [s]

  output_buffer = deque()

  while s is not None: 
    #Prevents select from returning the writeable socket when there's nothing to write
    if (len(output_buffer) > 0):
      outputs = [s]
    else:
      outputs = []

    readable, writeable, exceptional = select.select(inputs, outputs, inputs)

    if s in readable:
      data = s.recv(datalen)
      #print "received packet, length "+str(len(data))

      if ((data is not None) and (len(data) > 0)):
        data = decodemessage(data, crypt)
        sys.stdout.write(data) #Assuming that stdout is always writeable
      else:
        #Socket was closed remotely
        s.close()
        s = None

    if sys.stdin in readable:
      data = sys.stdin.readline(1024)
      if(len(data) > 0):
        for datapiece in [data[i:i+datalen-48] for i in range(0,len(data),datalen-48)]:
          datapiece = encodemessage(datapiece, crypt)
          output_buffer.append(datapiece)
      else:
        #EOF encountered, close if the local socket output buffer is empty.
        if( len(output_buffer) == 0):
          s.shutdown(socket.SHUT_RDWR)
          s.close()
          s = None

    if s in writeable:
      if (len(output_buffer) > 0):
        data = output_buffer.popleft()
        bytesSent = s.send(data)
        #If not all the characters were sent, put the unsent characters back in the buffer
        if(bytesSent < len(data)):
          output_buffer.appendleft(data[bytesSent:])

    if s in exceptional:
      s.shutdown(socket.SHUT_RDWR)
      s.close()
      s = None

###########

if __name__ == "__main__":
  main()

