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