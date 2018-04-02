# Does not work on Windows, tested on Ubuntu Linux 17.10
# Must run with root privileges to access raw sockets

import select
import struct
import sys
import os
import socket
import time

TIMEOUT = 2.0
ATTEMPTS = 3
ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30


def calcChecksum(packet):
    # Calculates a checksum based on the header and data in the ICMP packet
    # reference: http://www.faqs.org/rfcs/rfc1071.html
    length = len(packet)
    stop = (length / 2) * 2
    counter = 0
    checksum = 0

    while counter < stop:
        thisVal = packet[counter+1] * 256 + packet[counter]
        checksum = checksum + thisVal
        checksum = checksum & 0xffffffff
        counter = counter + 2

    if stop < length:
        checksum = checksum + packet[length - 1]
        checksum = checksum & 0xffffffff

    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum = checksum + (checksum >> 16)
    checksum = ~checksum
    checksum = checksum & 0xffff
    checksum = checksum >> 8 | (checksum << 8 & 0xff00)
    return checksum


def buildICMPPacket():
    # Packet structure: [[header(64)][data]]
    # Header structure: [[type(8)][code(8)][checksum(16)][id(16)][seq(16)]]

    # Make a header with a checksum of 0
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, 1, 1)
    data = struct.pack("d", time.time())

    # Calculate the real checksum on the 0 checksum header and data
    checksum = calcChecksum(header + data)

    # Put real checksum in the header
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, checksum, 1, 1)
    packet = header + data

    return packet


def getNameString(hostip):
    # Returns the host name if it can be accessed, otherwise
    # returns the IP address
    try:
        host = socket.gethostbyaddr(hostip)
        nameorip = '{0} ({1})'.format(host[0], hostip)
    except Exception:
        nameorip = '{0} ({0})'.format(hostip)
    return nameorip


def traceroute(target):
    print ("traceroute to " + target + ", " + str(MAX_HOPS) + " hops max")

    for i in range(1, MAX_HOPS):
        for j in range(ATTEMPTS):
            # Create a raw socket
            icmp = socket.getprotobyname("icmp")
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            sock.setsockopt(socket.IPPROTO_IP,
                            socket.IP_TTL, struct.pack('I', i))
            sock.settimeout(TIMEOUT)

            try:
                # build packet, send packet, receive packet
                d = buildICMPPacket()
                t = time.time()
                sock.sendto(d, (target, 0))
                recvPacket, addr = sock.recvfrom(1024)
                timeReceived = time.time()
            except socket.timeout:
                continue  # try again if we don't receive anything
            else:
                # Extract the icmp type from the IP packet
                icmpHeader = recvPacket[20:28]
                typ, code, checksum, packetid, seq = struct.unpack(
                    "bbHHh", icmpHeader)

                # Build the message to print
                # types:
                # 0 = Echo reply
                # 3 = Destination unreachable
                # 11 = Time exceeded
                if typ == 0:
                    # if we got a reply, get the originate timestamp out of the packet
                    t = struct.unpack(
                        "d", recvPacket[28:28 + struct.calcsize("d")])[0]
                if typ == 11 or typ == 3 or typ == 0:
                    # otherwise just use the time when we found out the destination was unreachable or timed out
                    message = " %d %s %.0f ms" % (
                        i, getNameString(addr[0]), (timeReceived - t)*1000)
                    if typ == 0:
                        return
                else:
                    message = "error"

                print(message)
                break  # don't try again if we succedded
            finally:
                sock.close()


traceroute(sys.argv[1])  # Accepts first command line argument (url)
