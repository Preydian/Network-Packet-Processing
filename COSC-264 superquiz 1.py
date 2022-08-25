def compose_header(version, hdrlen, tosdscp, totallength, identification, flags, fragmentoffset, timetolive, protocoltype, headerchecksum, sourceaddress, destinationaddress):
    '''f'''
    holding = bytearray(20)
    if version != 4:
        return 1
    if hdrlen.bit_length() > 4 or hdrlen < 0:
        return 2
    if tosdscp.bit_length() > 6 or tosdscp < 0:
        return 3  
    if totallength.bit_length() > 16 or totallength < 0:
        return 4  
    if identification.bit_length() > 16 or identification < 0:
        return 5
    if flags.bit_length() > 3 or flags < 0:
        return 6
    if fragmentoffset.bit_length() > 13 or fragmentoffset < 0:
        return 7
    if timetolive.bit_length() > 8 or timetolive < 0:
        return 8    
    if protocoltype.bit_length() > 8 or protocoltype < 0:
        return 9
    if headerchecksum.bit_length() > 16 or headerchecksum < 0:
        return 10
    if sourceaddress.bit_length() > 32 or sourceaddress < 0:
        return 11    
    if destinationaddress.bit_length() > 32 or destinationaddress < 0:
        return 12
    else:
        holding[0] = (version << 4) + hdrlen
        holding[1] = (tosdscp << 2)
        holding[2] = (totallength >> 8)
        holding[3] = (totallength) & 0xff
        holding[4] = (identification >> 8)
        holding[5] = (identification) & 0xff
        holding[6] = (flags << 5) + (fragmentoffset >> 8 & 0x1f)
        holding[7] = (fragmentoffset) & 0xff
        holding[8] = timetolive
        holding[9] = protocoltype
        holding[10] = (headerchecksum >> 8)
        holding[11] = (headerchecksum) & 0xff
        holding[12] = (sourceaddress >> 24)
        holding[13] = (sourceaddress >> 16) & 0xff
        holding[14] = (sourceaddress >> 8) & 0xff
        holding[15] = (sourceaddress) & 0xff
        holding[16] = (destinationaddress >> 24)
        holding[17] = (destinationaddress >> 16) & 0xff
        holding[18] = (destinationaddress >> 8) & 0xff
        holding[19] = (destinationaddress) & 0xff   
        return holding

def basic_packet_check(packet):
    '''f'''
    if len(packet) < 20:
        return 1
    if (packet[0] >> 4 )!= 4:
        return 2
    x = ((packet[0] << 8) | packet[1]) + ((packet[2] << 8) | packet[3]) + ((packet[4] << 8) | packet[5]) + ((packet[6] << 8) | packet[7]) + ((packet[8] << 8) | packet[9]) + ((packet[10] << 8) | packet[11]) + ((packet[12] << 8) | packet[13]) + ((packet[14] << 8) | packet[15]) + ((packet[16] << 8) | packet[17]) + ((packet[18] << 8) | packet[19])
    while x > 0xFFFF:
        y = x & 0xFFFF
        z = x >> 16  
        x = z + y
    if x != 0xFFFF:
        return 3
    if packet[3] != len(packet):
        return 4
    else: return True
    
def destination_address(packet):
    '''f'''
    addr = (packet[16] << 24 | packet[17] << 16 | packet[18] << 8 | packet[19])
    return (addr, '{}.{}.{}.{}'.format(packet[16], packet[17], packet[18], packet[19]))

def payload(packet):
    '''f'''
    hdrlen = packet[0] & 0x1f
    return packet[hdrlen*4:]

def compose_packet(hdrlen, tosdscp, identification, flags, fragmentoffset, timetolive, protocoltype, sourceaddress, destinationaddress, payload):
    '''f'''
    holding = bytearray(hdrlen * 4)
    version = 4
    totallength = (hdrlen * 4) + len(payload)
    if hdrlen > 15 or hdrlen < 5:
        return 2
    if tosdscp < 0 or tosdscp > 63:
        return 3
    if totallength < 0 or totallength > 65535:
        return 4
    if identification < 0 or identification > 65535:
        return 5
    if flags < 0 or flags > 7:
        return 6
    if fragmentoffset < 0 or fragmentoffset > 8191:
        return 7
    if timetolive < 0 or timetolive > 255:
        return 8
    if protocoltype < 0 or protocoltype > 255:
        return 9 
    if sourceaddress < 0 or sourceaddress > 4294967295:
        return 11
    if destinationaddress < 0 or destinationaddress > 4294967295:
        return 12       
    headerchecksum = 0
    holding[0] = (version << 4) + hdrlen
    holding[1] = (tosdscp << 2)
    holding[2] = (totallength >> 8)
    holding[3] = (totallength) & 0xff
    holding[4] = (identification >> 8)
    holding[5] = (identification) & 0xff
    holding[6] = (flags << 5) + (fragmentoffset >> 8 & 0x1f)
    holding[7] = (fragmentoffset) & 0xff
    holding[8] = timetolive
    holding[9] = protocoltype
    holding[10] = (headerchecksum >> 8)
    holding[11] = (headerchecksum) & 0xff
    holding[12] = (sourceaddress >> 24)
    holding[13] = (sourceaddress >> 16) & 0xff
    holding[14] = (sourceaddress >> 8) & 0xff
    holding[15] = (sourceaddress) & 0xff
    holding[16] = (destinationaddress >> 24)
    holding[17] = (destinationaddress >> 16) & 0xff
    holding[18] = (destinationaddress >> 8) & 0xff
    holding[19] = (destinationaddress) & 0xff    
    n = (hdrlen * 4)

    for i in range(n):
        if (i % 2 == 0):
            value = holding[i] << 8
        else:
            value = holding[i] 
        headerchecksum += value
    while headerchecksum > 0xFFFF:
        y = headerchecksum & 0xFFFF
        z = headerchecksum >> 16
        headerchecksum = y + z
    headerchecksum = ~headerchecksum & 0xFFFF
    holding[10] = (headerchecksum >> 8) & 0xFF
    holding[11] = headerchecksum & 0xFF
    if headerchecksum < 0 or headerchecksum > 65535:
        return 10
    else:
        return holding + payload


packet = compose_packet(6, 24, 4711, 0, 22, 64, 0x06, 0x22334455, 0x66778899, bytearray([0x10, 0x11, 0x12, 0x13, 0x14, 0x15]))
answer = '4660001e1267001640061165223344556677889900000000101112131415'
array = bytearray.fromhex(answer)
