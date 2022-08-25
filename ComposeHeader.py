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