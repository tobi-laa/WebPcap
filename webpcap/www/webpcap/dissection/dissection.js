var oldPacket = null; // cache for previously received data
var packets = [];
var rawPackets = [];
var tcpConns = {};

var counter = 1;

function dissect(data, f) {
    if (oldPacket !== null) { // consider previously received data
        data = appendBuffer(oldPacket, data);
        oldPacket = null;
    }
    
    if (data.byteLength < 16) { // i.e. not enough for pcap header
        oldPacket = data;
        return null;
    }
    
    var packet = new Pcaph(data, 0);
    
    if (data.byteLength < (packet.incl_len + 16)) { // i.e. packet not complete
        oldPacket = data; // store for next call to dissect
        return null;
    }   
    
    packet.num = counter;
    packet.next_header =
    dissectLinkLayer(packet, data, Pcaph.HLEN); // dissect further  
    
    if(f) f(packet); // callback
    
    // store dissected and raw packet
    packets[counter] = packet;
    rawPackets[counter] = data.slice(0, packet.incl_len + 16);
    counter++;  
    
    // see if there is more data to dissect
    if (packet.incl_len > 0 && data.byteLength > (packet.incl_len + 16))
        dissect(data.slice(packet.incl_len + 16), f);
}

function dissectLinkLayer(packet, data, offset) {
    // FIXME probably should be variable
    var toReturn = new Ethh(data, offset);       
    packet.src  = Ethh.printMAC(toReturn.src);
    packet.dst  = Ethh.printMAC(toReturn.dst);
    packet.prot = "Ethernet";
    toReturn.next_header = 
    dissectNetworkLayer(packet, data, offset + Ethh.HLEN, toReturn);    
    return toReturn;
}

function dissectNetworkLayer(packet, data, offset, parent) {
    var toReturn;
    switch(parent.prot) {
    case 0x0800: // IPv4
        toReturn = new IPv4h(data, offset);
        packet.src  = IPv4h.printIP(toReturn.src);
        packet.dst  = IPv4h.printIP(toReturn.dst);
        packet.prot = "IPv4";
        toReturn.next_header = 
        dissectTransportLayer(packet, data, offset + toReturn.getHeaderLength(), toReturn);
        break;
    case 0x86DD: // IPv6
        toReturn = new IPv6h(data, offset);   
        packet.src  = IPv6h.printIP(toReturn.src);
        packet.dst  = IPv6h.printIP(toReturn.dst);
        packet.prot = "IPv6";        
        toReturn.next_header = 
        dissectTransportLayer(packet, data, offset + IPv6h.HLEN, toReturn);
        break;
    case 0x0806: // ARP    
        toReturn = new ARPh(data, offset);
        packet.prot = "ARP";
        break;
    case 0x8035: // RARP
        toReturn = null;
        packet.prot = "RARP";
        break;
    default: // "unknown" ethtype
        toReturn = null;
        break;
    }
    return toReturn;
}

function dissectTransportLayer(packet, data, offset, parent) {
    var toReturn;
    switch(parent.prot) {
    case 1: // ICMP
        toReturn = null;      
        packet.prot = "ICMP";
        break;
    case 6: // TCP
        toReturn = new TCPh(data, offset, parent);
        packet.tcp_id = toReturn.id;
        
        if (!tcpConns[toReturn.id]) tcpConns[toReturn.id] = [packet];
        else tcpConns[toReturn.id].push(packet);
        
        packet.prot = "TCP";
        toReturn.next_header = 
        dissectApplicationLayer(packet, data, offset + toReturn.getHeaderLength(), toReturn);
        break;
    case 17: // UDP
        toReturn = new UDPh(data, offset);
        packet.prot = "UDP";
        toReturn.next_header = 
        dissectApplicationLayer(packet, data, offset + toReturn.getHeaderLength(), toReturn);
        break;
    default:
        toReturn = null;
        break;
    }  
    return toReturn;
}

function dissectApplicationLayer(packet, data, offset, parent) {
    if (parent.sport === 6600 || parent.dport === 6600)
        packet.prot = "MPD";
    else if (parent.sport === 80 || parent.dport === 80)
        packet.prot = "HTTP";
    return null;
/*  if (offset < ph.incl_len) {
        var buff = new Uint8Array(msg.data, offset);
        buff = String.fromCharCode.apply(String, buff);
        info += buff;
    }
    if (tl.sport === 6600 || tl.dport === 6600) {
        prot = "MPD";
        info += buff;
    }
    else if(buff === "GET " || buff ==="HTTP") {
        prot = "HTTP";
        tr_class = "http";
    }*/    
} 

function getPacket(num) {
    return packets[num];
}

function getPackets() {
    return packets;
}

function getTCPConn(id) {
    return tcpConns[id];
}

function getRawPacket(num) {
    return rawPackets[num];
}