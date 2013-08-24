'use strict';

if (typeof require !== 'undefined') {
    var Packet = require('./packet').Packet;
    Packet.HEADER_LENGTH = require('./packet').HEADER_LENGTH;
    var Ethernet = require('./ethernet').Ethernet;
    var SLL = require('./sll').SLL;
    var printMAC = require('./ethernet').printMAC;
    var IPv4 = require('./ipv4').IPv4;
    var IPv6 = require('./ipv6').IPv6;
    var ARP = require('./arp').ARP;
    var TCP = require('./tcp').TCP;
    var UDP = require('./udp').UDP;
    var DNS = require('./dns').DNS;
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
    this.nanoSecondAccuracy = false; // default is microseconds
    this.validateChecksums = false; // avoid offloading bugs...
}

Dissector.prototype.setLinkLayerType = function (newType) {
    this.linkLayerType = newType;
}

Dissector.prototype.setLittleEndian = function (littleEndian) {
    // note that this value is negated for dissection (network-byte-order!)
    this.littleEndian = littleEndian;
}

Dissector.prototype.setNanoSecondAccuracy = function (nanoSecondAccuracy) {
    this.nanoSecondAccuracy = nanoSecondAccuracy;
}

Dissector.prototype.setValidateChecksums = function (validateChecksums) {
    this.validateChecksums = validateChecksums;
}

Dissector.prototype.dissect = function (data) {
    while (data.byteLength > 0) {
        var packet; // the packet we're currently dissecting
        var packetLen;
        var dataView; // used to extract values from arraybuffers
        
        
        data = mergeBuffers([this.cache, data]); // add previously received data
        this.cache = null;
        
        if (data.byteLength < Packet.HEADER_LENGTH) { // not enough for header
            this.cache = data;
            return;
        }
        
        packetLen = new DataView(data, 0, Packet.HEADER_LENGTH).getUint32(
                            8, this.littleEndian) + Packet.HEADER_LENGTH;
        
        if (data.byteLength < packetLen) { // i.e. packet not complete
            this.cache = data; // store for next call to dissect
            return;
        }
        
        // store raw packet data
        this.rawPackets[this.counter - 1] = data.slice(0, packetLen);
        // make values accessible via dataview
        dataView = new DataView(this.rawPackets[this.counter - 1]);
        // dissect pcap header
        packet = new Packet(this.littleEndian, dataView, 0, this.counter, 
                            this.nanoSecondAccuracy);
        // store dissected packet
        this.dissectedPackets[this.counter - 1] = packet;
        // increase counter
        this.counter++;
        
        // dissect further
        packet.next_header = this.dissectLinkLayer(packet, dataView,
                                                   Packet.HEADER_LENGTH); 

        // see if there is more data to dissect
        if (packet.incl_len > 0 && data.byteLength > packetLen)
            data = data.slice(packetLen);        
        else
            return;
    }
}

Dissector.prototype.dissectLinkLayer = function (packet, dataView, offset) {
    var linkLayerHeader = null;
    
    if (offset > packet.incl_len + Packet.HEADER_LENGTH) { // bogus value
        packet.class = 'malformed';
        packet.val = false;
        return linkLayerHeader; // stop dissection
    }
    
    switch(this.linkLayerType) {
    case 113: // SLL
        linkLayerHeader = new SLL(!this.littleEndian, packet, dataView, offset);
        break;
    case 1: // Ethernet
        linkLayerHeader = new Ethernet(!this.littleEndian, packet, dataView, 
                                       offset);
        break;
    default: // something went wrong.. 
        throw 'Unsupported link layer type!';
    }
    linkLayerHeader.next_header = this.dissectNetworkLayer(packet, dataView, 
                                              offset + 
                                              linkLayerHeader.getHeaderLength(), 
                                              linkLayerHeader);
    return linkLayerHeader;
}

Dissector.prototype.dissectNetworkLayer = function (packet, dataView, offset, 
                                                    parent)
{
    var networkLayerHeader = null;
    
    if (offset > packet.incl_len + Packet.HEADER_LENGTH) { // bogus value
        packet.class = 'malformed';
        packet.val = false;
        return networkLayerHeader; // stop dissection
    }
    
    switch(parent.prot) {
    case 0x0800: // IPv4
        networkLayerHeader = new IPv4(!this.littleEndian, packet, dataView, 
                                      offset, this.validateChecksums);
        
        if (packet.val) { // if checksum was okay
            networkLayerHeader.next_header = this.dissectTransportLayer(packet, 
                dataView, offset + networkLayerHeader.getHeaderLength(), 
                networkLayerHeader);            
        }
        
        break;
    case 0x86DD: // IPv6
        networkLayerHeader = new IPv6(!this.littleEndian, packet, dataView, 
                                      offset);
        
        networkLayerHeader.next_header = this.dissectTransportLayer(packet, 
            dataView, offset + networkLayerHeader.getHeaderLength(), 
            networkLayerHeader);
        break;
    case 0x0806: // ARP    
        networkLayerHeader = new ARP(!this.littleEndian, packet, dataView, 
                                     offset);        
        break;
        
    // if unsupported ethtype, stop dissecting..
    // default: // so do nothing here
    }
    
    return networkLayerHeader;
}

Dissector.prototype.dissectTransportLayer = function (packet, dataView, offset, 
                                                      parent)
{
    var transportLayerHeader = null;
    
    if (offset > packet.incl_len + Packet.HEADER_LENGTH) { // bogus value
        packet.val = false;
        packet.class = 'malformed';
        return transportLayerHeader;
    }
    
    switch(parent.prot || parent.nh) { // different names for IPv4 and IPv6
    case 6: // TCP
        transportLayerHeader = new TCP(!this.littleEndian, packet, dataView,
                                       offset, parent, this.validateChecksums);
        
        this.handleConnection(packet, dataView, offset, parent, 
                              transportLayerHeader);
        
        transportLayerHeader.next_header = this.dissectApplicationLayer(packet,
            dataView, offset + transportLayerHeader.getHeaderLength(), 
            transportLayerHeader);
    
        break;
    case 17: // UDP
        transportLayerHeader = new UDP(!this.littleEndian, packet, dataView,
                                       offset, parent, this.validateChecksums);
        
        
        this.handleConnection(packet, dataView, offset, parent, 
                              transportLayerHeader);
    
        transportLayerHeader.next_header = this.dissectApplicationLayer(packet,
            dataView, offset + transportLayerHeader.getHeaderLength(),
            transportLayerHeader);
        
        break;
    }
    
    return transportLayerHeader;
}

Dissector.prototype.handleConnection = function (packet, dataView, offset, 
                                                 parent, transportLayerHeader)
{
    if (!packet.id)
        return;
                    
    var connection;
    
    if (!this.connectionsById[packet.id]) {
        // create a new connection object and store it properly
        connection = new Connection(this.connectionsByArrival.length + 1, 
                                    packet,
                                    dataView.buffer,
                                    transportLayerHeader);
        this.connectionsById[packet.id] = connection;
        this.connectionsByArrival.push(connection);
    }
    else {
        // update the already existing connection object
        connection = this.connectionsById[packet.id];
        connection.update(packet);
    }
    
    if (!transportLayerHeader.seqn) // no TCP packet: we're done here
        return;
    
    // otherwise try to add this segment to connection's content
    offset += transportLayerHeader.getHeaderLength();
    connection.processSegment(packet, dataView.buffer, offset, parent, 
                              transportLayerHeader);
}

Dissector.prototype.dissectApplicationLayer = 
function (packet, dataView, offset, parent) {
    var applicationLayer = null;
    
    if (offset > packet.incl_len + Packet.HEADER_LENGTH) { // bogus value
        packet.val = false;
        packet.class = 'malformed';
        return applicationLayer; // stop dissecting
    }
    
    if (parent.sport === 53 || parent.dport === 53) { // probably DNS
        applicationLayer = new DNS(!this.littleEndian, packet, dataView, offset,
                                   parent);
        
        if (applicationLayer.success) { // this worked, we can stop
            if (packet.id)
                this.connectionsById[packet.id].prot = 'DNS';
            
            return applicationLayer;
        }
    }
    
    else if (parent.sport === 6600 || parent.dport === 6600) { // maybe MPD
        applicationLayer = new MPD(!this.littleEndian, packet, dataView, offset, 
                                   parent);
        
        if (packet.id)
            this.connectionsById[packet.id].class = 'MPD';
        
        if (applicationLayer.success) { // this worked, we can stop
            if (packet.id)
                this.connectionsById[packet.id].prot = 'MPD';
            
            return applicationLayer;
        }
    }
    
    else if (parent.sport === 80 || parent.dport === 80 || 
             parent.sport === 8080 || parent.dport === 8080) 
    { // propably HTTP
        applicationLayer = new HTTP(!this.littleEndian, packet, dataView, 
                                    offset, parent);
        
        if (packet.id)
            this.connectionsById[packet.id].class = 'HTTP';
        
        if (applicationLayer.success) { // this worked, we can stop
            if (packet.id)
                this.connectionsById[packet.id].prot = 'HTTP';
            
            return applicationLayer;
        }
    }
    return applicationLayer;
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