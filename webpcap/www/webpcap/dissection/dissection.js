if (typeof require !== 'undefined') {
    var Pcaph = require('./Pcaph').Pcaph;
    var Ethh = require('./Ethh').Ethh;
    var SLLh = require('./SLLh').SLLh;
    var printMAC = require('./Ethh').printMAC;
    var printIPv4 = require('./IPv4h').printIPv4;
    var printIPv6 = require('./IPv6h').printIPv6;
    var IPv4h = require('./IPv4h').IPv4h;
    var IPv6h = require('./IPv6h').IPv6h;
    var ARPh = require('./ARPh');
    var TCPh = require('./TCPh').TCPh;
    var UDPh = require('./UDPh');
    var HTTPh = require('./HTTPh').HTTPh;
    var MPDh = require('./MPDh').MPDh;
    var Connection = require('./Connection').Connection;
    var appendBuffer = require('./../arrayBuffers').appendBuffer;
}

var PCAP_HEADER_LENGTH = 16;

function Dissector() {
    this.cache = null; // cache for previously received data
    this.dissectedPackets = [];
    this.rawPackets = [];
    
    // the following two variables will hold the same objects, but...
    this.connectionsById = {};      // .. these will be accessible via their ID
    this.connectionsByArrival = []; // .. these are stored chronologically

    this.counter = 1;
    this.linkLayerType = 113; // default is SLL
}

Dissector.prototype.setLinkLayerType = function (newType) {
    this.linkLayerType = newType;
}

Dissector.prototype.dissect = function (data) {
    while (data.byteLength > 0) {
        if (this.cache !== null) { // consider previously received data
            data = appendBuffer(this.cache, data);
            this.cache = null;
        }
        
        if (data.byteLength < PCAP_HEADER_LENGTH) { // i.e. not enough for pcap header
            this.cache = data;
            return;
        }
        
        var packet = new Pcaph(data, 0);
        
        if (data.byteLength < (packet.incl_len + PCAP_HEADER_LENGTH)) { // i.e. packet not complete
            this.cache = data; // store for next call to dissect
            return;
        }
                
        packet.num = this.counter;
        packet.next_header =
        this.dissectLinkLayer(packet, data.slice(0, packet.incl_len + PCAP_HEADER_LENGTH), PCAP_HEADER_LENGTH); // dissect further  
                
        // store dissected and raw packet
        this.dissectedPackets[this.counter - 1] = packet;
        this.rawPackets[this.counter - 1] = data.slice(0, packet.incl_len + PCAP_HEADER_LENGTH);
        this.counter++;
        
        // see if there is more data to dissect
        if (packet.incl_len > 0 && data.byteLength > (packet.incl_len + PCAP_HEADER_LENGTH))
            data = data.slice(packet.incl_len + PCAP_HEADER_LENGTH);        
        else
            return;
    }
}

Dissector.prototype.dissectLinkLayer = function (packet, data, offset) {
    var toReturn = null;
    if (offset > packet.incl_len + PCAP_HEADER_LENGTH) { // bogus value
        packet.class = 'malformed';
        return toReturn;
    }
    switch(this.linkLayerType) {
    case 113: // SLL
        toReturn = new SLLh(data, offset);       
        packet.src  = printMAC(toReturn.src);
        // packet.dst  = printMAC(toReturn.dst);
        packet.prot = 'SLL';
        break;
    case 1: // Ethernet
        toReturn = new Ethh(data, offset);       
        packet.src  = printMAC(toReturn.src);
        packet.dst  = printMAC(toReturn.dst);
        packet.prot = 'Ethernet';
        break;
    default:
        return toReturn; // i.e. return null
    }
    toReturn.next_header = this.dissectNetworkLayer(packet, data, 
                                               offset + 
                                               toReturn.getHeaderLength(), 
                                               toReturn);
    return toReturn;
}

Dissector.prototype.dissectNetworkLayer = function (packet, data, offset, parent) {
    if (offset > packet.incl_len + PCAP_HEADER_LENGTH) { // bogus value
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
        this.dissectTransportLayer(packet, data, offset + toReturn.getHeaderLength(), toReturn);
        if (!toReturn.val)
            packet.class = 'malformed';
        break;
    case 0x86DD: // IPv6
        toReturn = new IPv6h(data, offset);   
        packet.src  = printIPv6(toReturn.src);
        packet.dst  = printIPv6(toReturn.dst);
        packet.prot = 'IPv6';
        toReturn.next_header = 
        this.dissectTransportLayer(packet, data, offset + toReturn.getHeaderLength(), toReturn);
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

Dissector.prototype.dissectTransportLayer = function (packet, data, offset, parent) {
    var toReturn = null;
    
    if (offset > packet.incl_len + PCAP_HEADER_LENGTH) { // bogus value
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
        this.handleConnection(packet, data, offset, parent, toReturn);
        toReturn.next_header = 
        this.dissectApplicationLayer(packet, data, offset + toReturn.getHeaderLength(), toReturn);
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
        this.handleConnection(packet, data, offset, parent, toReturn);
        toReturn.next_header = 
        this.dissectApplicationLayer(packet, data, offset + toReturn.getHeaderLength(), toReturn);
        if (!toReturn.val)
            packet.class = 'malformed';
        break;
    }  
    return toReturn;
}

Dissector.prototype.handleConnection = function (packet, data, offset, parent, toReturn) {
    if (!toReturn.id)
        return;
        
    packet.id = toReturn.id; // make TCP/UDP id easily accessible
            
    var connection;
    
    if (!this.connectionsById[toReturn.id]) {
        // create a new connection object and store it properly
        connection = new Connection(this.connectionsByArrival.length + 1, 
                                    packet,
                                    data,
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
    connection.processSegment(packet, data, offset, parent, toReturn);
}

Dissector.prototype.dissectApplicationLayer = function (packet, data, offset, parent) {
    if (offset > packet.incl_len + PCAP_HEADER_LENGTH) { // bogus value
        packet.class = 'malformed';
        return null;
    }
    var toReturn = null;
    
    if (parent.sport === 6600 || parent.dport === 6600) {
        toReturn = new MPDh(data, offset, parent);
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
        toReturn = new HTTPh(data, offset, parent);
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