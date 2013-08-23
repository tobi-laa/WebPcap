'use strict';

if (typeof require !== 'undefined') {
    var printNum = require('../formattedoutput').printNum;
    var printMAC = require('./ethernet').printMAC;
    var Ethernet = require('./ethernet').Ethernet;
    Ethernet.TYPES = require('./ethernet').TYPES;
}

/*
 ******************************************************************
 ******************* LINUX 'COOKED' CAPTURE ***********************
 ******************************************************************
 */

function SLL(littleEndian, dataView, offset) {    
    this.type    = dataView.getUint16(offset, littleEndian);                 // packet type
    this.llat    = dataView.getUint16(offset + 2, littleEndian);                 // link-layer address type
    this.llal    = dataView.getUint16(offset + 4, littleEndian);                 // link-layer address length
    this.src     = new DataView(dataView.buffer, offset + 6, this.llal); // source (MAC) address    
    this.prot    = dataView.getUint16(offset + 14, littleEndian);                 // protocol (i.e. IPv4)
    
    this.next_header = null;
}

SLL.prototype = {
    getHeaderLength: function () {
        return SLL.HEADER_LENGTH;
    },
    toString: function () {
        return 'From:  ' + printMAC(this.src);
    }
};

SLL.prototype.printDetails = function () {
    var title = 'Linux cooked capture';
    var nodes = []
    
    nodes.push(document.createTextNode(
        [
        'Packet type: ' + printPacketType(this.type) + ' (' + this.type + ')',
        'Link-layer address type: ' + this.llat,
        'Link-layer address length: ' + this.llal,
        'Source: ' + printMAC(this.src),
        'Protocol: ' + Ethernet.TYPES[this.prot] + ' (0x' + printNum(this.prot, 16, 4) + ')'
        ].join('\n')
    ));
    
    return createDetails(title, nodes);
}

function printPacketType(type) {
    switch(type) {
    case 0:  return 'Unicast to us';
    case 1:  return 'Broadcast';
    case 2:  return 'Multicast';
    case 3:  return 'Unicast to another host';
    case 4:  return 'Sent by us';
    default: return 'Unknown';
    }
}

SLL.HEADER_LENGTH = 16; // SLL header length in bytes

if (typeof module !== 'undefined') {
    module.exports.HEADER_LENGTH = SLL.HEADER_LENGTH;
    module.exports.SLL = SLL;
}