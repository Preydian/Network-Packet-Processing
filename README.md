# Network-Packet-Processing
Description:
------------------------------------------------------------------------------------------------------------------------
Collection of Python functions that are used to process network packets

Instructions:
------------------------------------------------------------------------------------------------------------------------
1.) BasicPakcetCheck takes a bytearry of a packets header (No payload) and returns True or False depending on the validity of the packet. 
An example call is as follows:
packet = bytearray([0x45, 0x0, 0x0, 0x1e, 0x4, 0xd2, 0x0, 0x0, 0x40, 0x6, 0x20, 0xb4, 0x12, 0x34, 0x56, 0x78, 0x98, 0x76, 0x54, 0x32, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])
print(basic_packet_check(packet))

2.) ComposeHeader takes the 12 unique fields of a packet header and returns a bytearray. (Excluding unused bits)
An example call is as follows:
header = compose_header(4,5,0,1500,24200,0,63,22,6,4711, 2190815565, 3232270145)
print(header.hex())
Since Python doesn't consistenly print the bytearrays context you should hex the returned array.

3.) ComposePacket takes 9 of the 12 unique header fields along with a bytearray as the paylod.
The missing fields are: Version, TotalLength and HeaderCheckSum
Version is set to 4 by default and both the TotalLength and HeaderCheckSum are calculated inside the function.
An exmaple call is as follows:
packet = compose_packet(6, 24, 4711, 0, 22, 64, 0x06, 0x22334455, 0x66778899, bytearray([0x10, 0x11, 0x12, 0x13, 0x14, 0x15]))
print(packet.hex())

4.) DestinationAndPayloadExtraction both take in a bytearray with slight difference.
DestinationAddress function takes a packet and returns the destinationaddress field in both 32-bit and DD form.
Example for  calls are as follows:
packet = bytearray([0x45, 0x00, 0x00, 0x1e, 0x04, 0xd2, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x33, 0x44, 0x55, 0x66])
print(destination_address(packet))

Payload function takes a packet and returns the payload in a bytearray.
packet = bytearray([0x45, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x69, 0x8d, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x10, 0x11, 0x12])
print(payload(packet))

5.) PacketProcessing just contains all the functions mentioned above.
