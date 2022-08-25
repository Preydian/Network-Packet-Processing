def destination_address(packet):
    '''f'''
    addr = (packet[16] << 24 | packet[17] << 16 | packet[18] << 8 | packet[19])
    return (addr, '{}.{}.{}.{}'.format(packet[16], packet[17], packet[18], packet[19]))

def payload(packet):
    '''f'''
    hdrlen = packet[0] & 0x1f
    return packet[hdrlen*4:]