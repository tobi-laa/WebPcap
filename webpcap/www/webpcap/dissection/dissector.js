'use strict';

if (typeof require !== 'undefined') {
    var Packet = require('./packet').Packet;
    Packet.HEADER_LENGTH = require('./packet').HEADER_LENGTH;
    var Ethernet = require('./ethernet').Ethernet;
    var SLL = require('./sll').SLL;
    var printMAC = require('./ethernet').printMAC;
    var printIPv4 = require('./ipv4').printIPv4;
    var printIPv6 = require('./ipv6').printIPv6;
    var IPv4 = require('./ipv4').IPv4;
    var IPv6 = require('./ipv6').IPv6;
    var ARP = require('./arp').ARP;
    var TCP = require('./tcp').TCP;
    var UDP = require('./udp').UDP;
    var HTTP = require('./http').HTTP;
    var MPD = require('./mpd').MPD;
    var Connection = require('./connection').Connection;
    var mergeBuffers = require('./../arraybuffers').mergeBuffers;
}

function Dissector() {
    this.cache = null; // cache for previously received data
    this.init();
}

Dissector.prototype.init = function () {
    // don't touch this.cache, that might break everything
    this.dissectedPackets = [];
    this.rawPackets = [];
    
    // the following two variables will hold the same objects, but...
    this.connectionsById = {};      // .. these will be accessible via their ID
    this.connectionsByArrival = []; // .. these are stored chronologically

    this.counter = 1;
    this.linkLayerType = 113; // default is SLL
    this.littleEndian = true;
}

Dissector.prototype.setLinkLayerType = function (newType) {
    this.linkLayerType = newType;
}

Dissector.prototype.setLittleEndian = function (littleEndian) {
    // note that this value is negated for dissection (network-byte-order!)
    this.littleEndian = littleEndian;
}

Dissector.prototype.dissect = function (data) {
    while (data.byteLength > 0) {
        data = mergeBuffers([this.cache, data]); // consider previously received data
        this.cache = null;
        
        if (data.byteLength < Packet.HEADER_LENGTH) { // i.e. not enough for pcap header
            this.cache = data;
            return;
        }
        
        var packetLen = new DataView(data, 0, Packet.HEADER_LENGTH)
                            .getUint32(8, this.littleEndian)
                            + Packet.HEADER_LENGTH;
        
        if (data.byteLength < packetLen) { // i.e. packet not complete
            this.cache = data; // store for next call to dissect
            return;
        }
        
        // store raw packet data
        this.rawPackets[this.counter - 1] = data.slice(0, packetLen);
        // make values accessible via dataview
        var dataView = new DataView(this.rawPackets[this.counter - 1]);
        // dissect pcap header
        var packet = new Packet(this.littleEndian, dataView, 0);
        
        packet.num = this.counter;
        packet.next_header =
        this.dissectLinkLayer(packet, dataView, Packet.HEADER_LENGTH); // dissect further  
                
        // store dissected packet
        this.dissectedPackets[this.counter - 1] = packet;
        
        this.counter++;
        
        // see if there is more data to dissect
        if (packet.incl_len > 0 && data.byteLength > packetLen)
            data = data.slice(packetLen);        
        else
            return;
    }
}

Dissector.prototype.dissectLinkLayer = function (packet, dataView, offset) {
    var toReturn = null;
    if (offset > packet.incl_len + Packet.HEADER_LENGTH) { // bogus value
        packet.class = 'malformed';
        return toReturn;
    }
    switch(this.linkLayerType) {
    case 113: // SLL
        toReturn = new SLL(!this.littleEndian, dataView, offset);       
        packet.src  = printMAC(toReturn.src);
        // packet.dst  = printMAC(toReturn.dst);
        packet.prot = 'SLL';
        break;
    case 1: // Ethernet
        toReturn = new Ethernet(!this.littleEndian, dataView, offset);       
        packet.src  = printMAC(toReturn.src);
        packet.dst  = printMAC(toReturn.dst);
        packet.prot = 'Ethernet';
        break;
    default:
        return toReturn; // i.e. return null
    }
    toReturn.next_header = this.dissectNetworkLayer(packet, dataView, 
                                               offset + 
                                               toReturn.getHeaderLength(), 
                                               toReturn);
    return toReturn;
}

Dissector.prototype.dissectNetworkLayer = function (packet, dataView, offset, parent) {
    if (offset > packet.incl_len + Packet.HEADER_LENGTH) { // bogus value
        packet.class = 'malformed';
        return null;
    }
    var toReturn;
    switch(parent.prot) {
    case 0x0800: // IPv4
        toReturn = new IPv4(!this.littleEndian, dataView, offset);
        packet.src  = printIPv4(toReturn.src);
        packet.dst  = printIPv4(toReturn.dst);
        packet.prot = 'IPv4';
        toReturn.next_header = 
        this.dissectTransportLayer(packet, dataView, offset + toReturn.getHeaderLength(), toReturn);
        if (!toReturn.val)
            packet.class = 'malformed';
        break;
    case 0x86DD: // IPv6
        toReturn = new IPv6(!this.littleEndian, dataView, offset);   
        packet.src  = printIPv6(toReturn.src);
        packet.dst  = printIPv6(toReturn.dst);
        packet.prot = 'IPv6';
        toReturn.next_header = 
        this.dissectTransportLayer(packet, dataView, offset + toReturn.getHeaderLength(), toReturn);
        break;
    case 0x0806: // ARP    
        toReturn = new ARP(!this.littleEndian, dataView, offset);
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

Dissector.prototype.dissectTransportLayer = function (packet, dataView, offset, parent) {
    var toReturn = null;
    
    if (offset > packet.incl_len + Packet.HEADER_LENGTH) { // bogus value
        packet.class = 'malformed';
        return toReturn;
    }
    
    switch(parent.prot || parent.nh) {
    case 1: // ICMP
        toReturn = null;      
        packet.prot = 'ICMP';
        break;
    case 6: // TCP
        toReturn = new TCP(!this.littleEndian, dataView, offset, parent);        
        packet.prot = 'TCP';
        this.handleConnection(packet, dataView, offset, parent, toReturn);
        toReturn.next_header = 
        this.dissectApplicationLayer(packet, dataView, offset + toReturn.getHeaderLength(), toReturn);
        if (!toReturn.val)
            packet.class = 'malformed';
        else if (toReturn.RST)
            packet.class = 'RST';
        else if (toReturn.SYN || toReturn.FIN)
            packet.class = 'SYNFIN';
        break;
    case 17: // UDP
        toReturn = new UDP(!this.littleEndian, dataView, offset, parent);        
        packet.prot = 'UDP';
        this.handleConnection(packet, dataView, offset, parent, toReturn);
        toReturn.next_header = 
        this.dissectApplicationLayer(packet, dataView, offset + toReturn.getHeaderLength(), toReturn);
        if (!toReturn.val)
            packet.class = 'malformed';
        break;
    }  
    return toReturn;
}

Dissector.prototype.handleConnection = function (packet, dataView, offset, parent, toReturn) {
    if (!toReturn.id)
        return;
        
    packet.id = toReturn.id; // make TCP/UDP id easily accessible
            
    var connection;
    
    if (!this.connectionsById[toReturn.id]) {
        // create a new connection object and store it properly
        connection = new Connection(this.connectionsByArrival.length + 1, 
                                    packet,
                                    dataView.buffer,
                                    toReturn);
        this.connectionsById[toReturn.id] = connection;
        this.connectionsByArrival.push(connection);
    }
    else {
        // update the already existing connection object
        connection = this.connectionsById[toReturn.id];
        connection.update(packet);
    }
    
    if (!toReturn.seqn) // no TCP packet: we're done here
        return;
    
    // otherwise try to add this segment to connection's content
    offset += toReturn.getHeaderLength();
    connection.processSegment(packet, dataView.buffer, offset, parent, toReturn);
}

Dissector.prototype.dissectApplicationLayer = 
function (packet, dataView, offset, parent) {
    if (offset > packet.incl_len + Packet.HEADER_LENGTH) { // bogus value
        packet.class = 'malformed';
        return null;
    }
    var toReturn = null;
    
    if (parent.sport === 53 || parent.dport === 53) { // probably DNS
        toReturn = new DNS(!this.littleEndian, dataView, offset, parent);
        packet.prot = 'DNS';
        this.connectionsById[packet.id].prot = 'DNS';
    }
    
    else if (parent.sport === 6600 || parent.dport === 6600) {
        toReturn = new MPD(!this.littleEndian, dataView, offset, parent);
        this.connectionsById[packet.id].class = 'MPD';
        packet.class = 'MPD';
        if (!toReturn.type)
            toReturn = null;
        else {
            this.connectionsById[packet.id].prot = 'MPD';
            packet.prot = 'MPD';
        }
    }
    
    else if (parent.sport === 80 || parent.dport === 80) {
        toReturn = new HTTP(!this.littleEndian, dataView, offset, parent);
        this.connectionsById[packet.id].class = 'HTTP';
        packet.class = 'HTTP';
        if (!toReturn.headers)
            toReturn = null;
        else {
            this.connectionsById[packet.id].prot = 'HTTP';
            packet.prot = 'HTTP';
        }
    }
    return toReturn;
} 

Dissector.prototype.getConnectionById = function (id) {
    return this.connectionsById[id];
}

Dissector.prototype.getConnectionsById = function () {
    return this.connectionsById;
}

Dissector.prototype.getConnectionByArrival = function (num) {
    return this.connectionsByArrival[num];
}

Dissector.prototype.getConnectionsByArrival = function () {
    return this.connectionsByArrival;
}

Dissector.prototype.getRawPacket = function (num) {
    return this.rawPackets[num - 1];
}

Dissector.prototype.getRawPackets = function () {
    return this.rawPackets;
}

Dissector.prototype.getDissectedPacket = function (num) {
    return this.dissectedPackets[num - 1];
}

Dissector.prototype.getDissectedPackets = function () {
    return this.dissectedPackets;
}

if (typeof module !== 'undefined') {
    module.exports.Dissector = Dissector;
}