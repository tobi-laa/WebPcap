var oldPacket = null; // cache for previously received data
var packets = [];
var rawPackets = [];
var tcpConns = {};

var counter = 1;

if (typeof require !== 'undefined') {
    var Pcaph = require('./Pcaph');
    var Ethh = require('./Ethh').Ethh;
    var printMAC = require('./Ethh').printMAC;
    var printIPv4 = require('./IPv4h').printIPv4;
    var printIPv6 = require('./IPv6h').printIPv6;
    var IPv4h = require('./IPv4h').IPv4h;
    var IPv6h = require('./IPv6h').IPv6h;
    var ARPh = require('./ARPh');
    var TCPh = require('./TCPh');
    var UDPh = require('./UDPh');
    var appendBuffer = require('./../arrayBuffers').appendBuffer;
}

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
    packets[counter - 1] = packet;
    rawPackets[counter - 1] = data.slice(0, packet.incl_len + 16);
    counter++;  
    
    // see if there is more data to dissect
    if (packet.incl_len > 0 && data.byteLength > (packet.incl_len + 16))
        dissect(data.slice(packet.incl_len + 16), f);
}

function dissectLinkLayer(packet, data, offset) {
    // FIXME probably should be variable
    var toReturn = new Ethh(data, offset);       
    packet.src  = printMAC(toReturn.src);
    packet.dst  = printMAC(toReturn.dst);
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
        packet.src  = printIPv4(toReturn.src);
        packet.dst  = printIPv4(toReturn.dst);
        packet.prot = "IPv4";
        toReturn.next_header = 
        dissectTransportLayer(packet, data, offset + toReturn.getHeaderLength(), toReturn);
        break;
    case 0x86DD: // IPv6
        toReturn = new IPv6h(data, offset);   
        packet.src  = printIPv6(toReturn.src);
        packet.dst  = printIPv6(toReturn.dst);
        packet.prot = "IPv6";        
        toReturn.next_header = 
        dissectTransportLayer(packet, data, offset + toReturn.getHeaderLength(), toReturn);
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
        
        if (!tcpConns[toReturn.id]) {
            tcpConns[toReturn.id] = new Object();
            tcpConns[toReturn.id].packets = [packet];        
            tcpConns[toReturn.id].src = printIPv4(parent.src);
            tcpConns[toReturn.id].dst = printIPv4(parent.dst);
            tcpConns[toReturn.id].sport = toReturn.sport;
            tcpConns[toReturn.id].dport = toReturn.dport;
            tcpConns[toReturn.id].num = 1;
            tcpConns[toReturn.id].len = packet.orig_len;
        }
        else {
            tcpConns[toReturn.id].packets.push(packet);
            tcpConns[toReturn.id].num++;
            tcpConns[toReturn.id].len += packet.orig_len;
        }
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
    return packets[num - 1];
}

function getPackets() {
    return packets;
}

function getTCPConn(id) {
    return tcpConns[id];
}

function getTCPConns() {
    return tcpConns;
}

function getRawPacket(num) {
    return rawPackets[num - 1];
}

if (typeof module !== 'undefined') {
    module.exports.dissect = dissect;
    module.exports.getTCPConns = getTCPConns;
}