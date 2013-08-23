'use strict';
if (typeof require !== 'undefined') 
    var printNum = require('../formattedoutput').printNum;

/*
 ******************************************************************
 ************************ ETHERNET HEADER *************************
 ******************************************************************
 */

function Ethernet(littleEndian, dataView, offset) {   
    this.dst  = new DataView(dataView.buffer, offset, Ethernet.ADDRESS_LENGTH);  // destination MAC address
    this.src  = new DataView(dataView.buffer, offset + 6, Ethernet.ADDRESS_LENGTH); // source MAC address    
    this.prot = dataView.getUint16(offset + 12, littleEndian); // protocol (i.e. IPv4)
    
    this.next_header = null;
}

Ethernet.prototype = {
    getHeaderLength: function () {
        return Ethernet.HEADER_LENGTH;
    },
    toString: function () {
        return 'From: ' + printMAC(this.src)+
               ' To: '  + printMAC(this.dst);
    }
};

Ethernet.prototype.printDetails = function () {
    var title = 'Ethernet II';
    var nodes = []
    
    nodes.push(document.createTextNode(
        [
        'Destination: ' + printMAC(this.dst),
        'Source: ' + printMAC(this.src),
        'Type: ' + Ethernet.TYPES[this.prot] + ' (0x' + 
            printNum(this.prot, 16, 4) + ')'
        ].join('\n')
    ));
    
    return createDetails(title, nodes);
}

Ethernet.HEADER_LENGTH = 14; // Ethernet frame length in bytes
Ethernet.ADDRESS_LENGTH = 6;  // MAC address length in bytes
Ethernet.TYPES = [];

function printMAC(mac) {
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
    module.exports.printMAC = printMAC;
    module.exports.HEADER_LENGTH = Ethernet.HEADER_LENGTH;
    module.exports.ADDRESS_LENGTH = Ethernet.ADDRESS_LENGTH;
    module.exports.TYPES = Ethernet.TYPES;
}