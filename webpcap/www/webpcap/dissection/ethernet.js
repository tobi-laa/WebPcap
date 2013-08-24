'use strict';
if (typeof require !== 'undefined') {
    var readCSVFile = require('../fileio').readCSVFile;
    var printNum = require('../formattedoutput').printNum;
}

function Ethernet(littleEndian, packet, dataView, offset) {   
    // destination MAC address
    this.dst  = new DataView(dataView.buffer, offset, Ethernet.ADDRESS_LENGTH);
    // source MAC address    
    this.src  = new DataView(dataView.buffer, offset + 6, 
                             Ethernet.ADDRESS_LENGTH); 
    // protocol (i.e. IPv4)
    this.prot = dataView.getUint16(offset + 12, littleEndian);
    
    // update general information
    packet.src  = Ethernet.printMAC(this.src);
    packet.dst  = Ethernet.printMAC(this.dst);
    packet.class = packet.prot = Ethernet.TYPES[this.prot];
    packet.info = this.toString();
    
    this.next_header = null;
}

Ethernet.prototype.getHeaderLength = function () {
    return Ethernet.HEADER_LENGTH;
}

Ethernet.prototype.toString = function () {
    return Ethernet.TYPES[this.prot];    
}

Ethernet.prototype.printDetails = function () {
    var title = 'Ethernet II';
    var nodes = []
    
    nodes.push(document.createTextNode(
        [
        'Destination: ' + Ethernet.printMAC(this.dst),
        'Source: ' + Ethernet.printMAC(this.src),
        'Type: ' + Ethernet.TYPES[this.prot] + ' (0x' + 
            printNum(this.prot, 16, 4) + ')'
        ].join('\n')
    ));
    
    return createDetails(title, nodes);
}

Ethernet.HEADER_LENGTH = 14; // Ethernet frame length in bytes
Ethernet.ADDRESS_LENGTH = 6;  // MAC address length in bytes
Ethernet.TYPES = readCSVFile(
    'webpcap/dissection/resources/ieee-802-numbers-1.csv', 0, 4);

Ethernet.printMAC = function (mac) {
    // check param for consistency
    if (!mac.getUint8)
        throw 'MAC address param has to be a DataView object.';
    if (mac.byteLength !== Ethernet.ADDRESS_LENGTH)
        console.log('Warning: Incorrect MAC address length.');
    
    var macFragments = [];
    for (var i = 0; i < mac.byteLength; i++)
        macFragments[i] = printNum(mac.getUint8(i), 16, 2);
    return macFragments.join(':');
}

if (typeof module !== 'undefined') {
    module.exports.Ethernet = Ethernet;
    module.exports.printMAC = Ethernet.printMAC;
    module.exports.HEADER_LENGTH = Ethernet.HEADER_LENGTH;
    module.exports.ADDRESS_LENGTH = Ethernet.ADDRESS_LENGTH;
    module.exports.TYPES = Ethernet.TYPES;
}