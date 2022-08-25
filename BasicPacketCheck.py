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