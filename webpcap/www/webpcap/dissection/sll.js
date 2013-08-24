'use strict';

if (typeof require !== 'undefined') {
    var printNum = require('../formattedoutput').printNum;
    var printMAC = require('./ethernet').printMAC;
    var Ethernet = require('./ethernet').Ethernet;
    Ethernet.printMAC = require('./ethernet').printMAC;
    Ethernet.TYPES = require('./ethernet').TYPES;
}

function SLL(littleEndian, packet, dataView, offset) {    
    this.type    = dataView.getUint16(offset, littleEndian);                 // packet type
    this.llat    = dataView.getUint16(offset + 2, littleEndian);                 // link-layer address type
    this.llal    = dataView.getUint16(offset + 4, littleEndian);                 // link-layer address length
    this.src     = new DataView(dataView.buffer, offset + 6, this.llal); // source (MAC) address    
    this.prot    = dataView.getUint16(offset + 14, littleEndian);                 // protocol (i.e. IPv4)
    
    // update general information
    packet.src = Ethernet.printMAC(this.src);
    packet.dst = 'unknown';
    packet.class = packet.prot = Ethernet.TYPES[this.prot];
    packet.info = this.toString();
    
    this.next_header = null;
}

SLL.prototype.getHeaderLength = function () {
    return SLL.HEADER_LENGTH;
}

SLL.prototype.toString = function () {
    return SLL.TYPES[this.type] || '';
}

SLL.prototype.printDetails = function () {
    var title = 'Linux cooked capture';
    var nodes = []
    
    nodes.push(document.createTextNode(
        [
        'Packet type: ' + (SLL.TYPES[this.type] || '') + ' (' + this.type + ')',
        'Link-layer address type: ' + this.llat,
        'Link-layer address length: ' + this.llal,
        'Source: ' + Ethernet.printMAC(this.src),
        'Protocol: ' + Ethernet.TYPES[this.prot] + ' (0x' + 
            printNum(this.prot, 16, 4) + ')'
        ].join('\n')
    ));
    
    return createDetails(title, nodes);
}

SLL.TYPES = ['Unicast to us', 'Broadcast', 'Multicast', 
             'Unicast to another host', 'Sent by us'];
SLL.HEADER_LENGTH = 16; // SLL header length in bytes

if (typeof module !== 'undefined') {
    module.exports.HEADER_LENGTH = SLL.HEADER_LENGTH;
    module.exports.SLL = SLL;
    module.exports.TYPES = SLL.TYPES;
}