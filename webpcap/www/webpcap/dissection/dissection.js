if (typeof require !== 'undefined') {
    var Pcaph = require('./Pcaph');
    var Ethh = require('./Ethh').Ethh;
    var SLLh = require('./SLLh').SLLh;
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

var oldPacket = null; // cache for previously received data
var dissectedPackets = [];
var rawPackets = [];
// the following two variables will hold the same objects, but...
var connectionsById = {};      // .. these will be accessible via their ID
var connectionsByArrival = []; // .. these are stored chronologically

var counter = 1;
var linkLayerType = 113; // default is SLL

function dissect(data) {
    while (true) {
        if (oldPacket !== null) { // consider previously received data
            data = appendBuffer(oldPacket, data);
            oldPacket = null;
        }
        
        if (data.byteLength < Pcaph.HLEN) { // i.e. not enough for pcap header
            oldPacket = data;
            return;
        }
        
        var packet = new Pcaph(data, 0);
        
        if (data.byteLength < (packet.incl_len + Pcaph.HLEN)) { // i.e. packet not complete
            oldPacket = data; // store for next call to dissect
            return;
        }   
        
        packet.num = counter;
        packet.next_header =
        dissectLinkLayer(packet, data.slice(0, packet.incl_len + Pcaph.HLEN), Pcaph.HLEN); // dissect further  
                
        // store dissected and raw packet
        dissectedPackets[counter - 1] = packet;
        rawPackets[counter - 1] = data.slice(0, packet.incl_len + Pcaph.HLEN);
        counter++;
        
        // see if there is more data to dissect
        if (packet.incl_len > 0 && data.byteLength > (packet.incl_len + Pcaph.HLEN))
            data = data.slice(packet.incl_len + Pcaph.HLEN);        
        else
            return;
    }
}

function dissectLinkLayer(packet, data, offset) {
    var toReturn = null;
    if (offset > packet.incl_len + Pcaph.HLEN) { // bogus value
        packet.class = 'malformed';
        return toReturn;
    }
    switch(linkLayerType) {
    case SLL:
        toReturn = new SLLh(data, offset);       
        packet.src  = printMAC(toReturn.src);
        // packet.dst  = printMAC(toReturn.dst);
        packet.prot = 'SLL';
        break;
    case ETHERNET:
        toReturn = new Ethh(data, offset);       
        packet.src  = printMAC(toReturn.src);
        packet.dst  = printMAC(toReturn.dst);
        packet.prot = 'Ethernet';
        break;
    default:
        return toReturn; // i.e. return null
    }
    toReturn.next_header = dissectNetworkLayer(packet, data, 
                                               offset + 
                                               toReturn.getHeaderLength(), 
                                               toReturn);
    return toReturn;
}

function dissectNetworkLayer(packet, data, offset, parent) {
    if (offset > packet.incl_len + Pcaph.HLEN) { // bogus value
        packet.class = 'malformed';
        return null;
    }
    var toReturn;
    switch(parent.prot) {
    case 0x0800: // IPv4
        toReturn = new IPv4h(data, offset);
        packet.src  = printIPv4(toReturn.src);
        packet.dst  = printIPv4(toReturn.dst);
        packet.prot = 'IPv4';
        toReturn.next_header = 
        dissectTransportLayer(packet, data, offset + toReturn.getHeaderLength(), toReturn);
        if (!toReturn.val)
            packet.class = 'malformed';
        break;
    case 0x86DD: // IPv6
        toReturn = new IPv6h(data, offset);   
        packet.src  = printIPv6(toReturn.src);
        packet.dst  = printIPv6(toReturn.dst);
        packet.prot = 'IPv6';
        toReturn.next_header = 
        dissectTransportLayer(packet, data, offset + toReturn.getHeaderLength(), toReturn);
        break;
    case 0x0806: // ARP    
        toReturn = new ARPh(data, offset);
        packet.prot = 'ARP';
        break;
    case 0x8035: // RARP
        toReturn = null;
        packet.prot = 'RARP';
        break;
    default: // 'unknown' ethtype
        toReturn = null;
        break;
    }
    return toReturn;
}

function dissectTransportLayer(packet, data, offset, parent) {
    var toReturn = null;
    
    if (offset > packet.incl_len + Pcaph.HLEN) { // bogus value
        packet.class = 'malformed';
        return toReturn;
    }
    
    switch(parent.prot || parent.nh) {
    case 1: // ICMP
        toReturn = null;      
        packet.prot = 'ICMP';
        break;
    case 6: // TCP
        toReturn = new TCPh(data, offset, parent);        
        packet.prot = 'TCP';
        handleConnection(packet, data, offset, parent, toReturn);
        toReturn.next_header = 
        dissectApplicationLayer(packet, data, offset + toReturn.getHeaderLength(), toReturn);
        if (!toReturn.val)
            packet.class = 'malformed';
        else if (toReturn.RST)
            packet.class = 'RST';
        else if (toReturn.SYN || toReturn.FIN)
            packet.class = 'SYNFIN';
        break;
    case 17: // UDP
        toReturn = new UDPh(data, offset, parent);        
        packet.prot = 'UDP';
        handleConnection(packet, data, offset, parent, toReturn);
        toReturn.next_header = 
        dissectApplicationLayer(packet, data, offset + toReturn.getHeaderLength(), toReturn);
        if (!toReturn.val)
            packet.class = 'malformed';
        break;
    }  
    return toReturn;
}

function handleConnection(packet, data, offset, parent, toReturn) {
    if (!toReturn.id)
        return;
        
    packet.id = toReturn.id; // make TCP/UDP id easily accessible
            
    var connection;
    
    if (!connectionsById[toReturn.id]) {
        // create a new connection object and store it properly
        connection = new Connection(connectionsByArrival.length + 1, 
                                    packet,
                                    data,
                                    toReturn);
        connectionsById[toReturn.id] = connection;
        connectionsByArrival.push(connection);
    }
    else {
        // update the already existing connection object
        connection = connectionsById[toReturn.id];
        connection.update(packet);
    }
    
    if (!toReturn.seqn) // no TCP packet: we're done here
        return;
    
    // otherwise try to add this segment to connection's content
    offset += toReturn.getHeaderLength();
    connection.processSegment(packet, data, offset, parent, toReturn);
}

function dissectApplicationLayer(packet, data, offset, parent) {
    if (offset > packet.incl_len + Pcaph.HLEN) { // bogus value
        packet.class = 'malformed';
        return null;
    }
    var toReturn = null;
    
    if (parent.sport === 6600 || parent.dport === 6600) {
        toReturn = new MPDh(data, offset, parent);
        connectionsById[packet.id].class = 'MPD';
        packet.class = 'MPD';
        if (!toReturn.type)
            toReturn = null;
        else {
            connectionsById[packet.id].prot = 'MPD';
            packet.prot = 'MPD';
        }
    }
    
    else if (parent.sport === 80 || parent.dport === 80) {
        toReturn = new HTTPh(data, offset, parent);
        connectionsById[packet.id].class = 'HTTP';
        packet.class = 'HTTP';
        if (!toReturn.headers)
            toReturn = null;
        else {
            connectionsById[packet.id].prot = 'HTTP';
            packet.prot = 'HTTP';
        }
    }
    return toReturn;
} 

function getDissectedPacket(num) {
    return dissectedPackets[num - 1];
}

function getDissectedPackets() {
    return dissectedPackets;
}

function getConnectionById(id) {
    return connectionsById[id];
}

function getConnectionsById() {
    return connectionsById;
}

function getConnectionsByArrival() {
    return connectionsByArrival;
}

function getRawPacket(num) {
    return rawPackets[num - 1];
}

function getRawPackets() {
    return rawPackets;
}

if (typeof module !== 'undefined') {
    module.exports.dissect = dissect;
    module.exports.getConnectionsById = getConnectionsById;
}
