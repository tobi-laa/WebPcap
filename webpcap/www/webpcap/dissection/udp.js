'use strict';
if (typeof require !== 'undefined') {
    var createID = require('./tcp').createID;
    var buildPseudoHeader = require('./tcp').buildPseudoHeader;
    var validateChecksum = require('./ipv4').validateChecksum;
}
/*
 ******************************************************************
 ************************** UDP HEADER ****************************
 ******************************************************************
 */
function UDP(littleEndian, dataView, offset, parent) {    
    this.sport = dataView.getUint16(offset, littleEndian); // source port
    this.dport = dataView.getUint16(offset + 2, littleEndian); // destination port
    this.len   = dataView.getUint16(offset + 4, littleEndian); // length of payload incl. UDP header
    this.csum  = dataView.getUint16(offset + 6, littleEndian); // header checksum
      
    this.id = createID(parent.src, this.sport, parent.dst, this.dport, 'u');
    
    if (offset + this.getHeaderLength() > dataView.length)
        this.val = false;
    else if (!this.csum) // UDP checksum is optional...
        this.val = true;
    else {
        var ph = buildPseudoHeader(littleEndian, dataView, offset, parent);
        this.val = validateChecksum(littleEndian, ph);
    }
        
    this.next_header = null;
}

UDP.prototype = {
    getHeaderLength: function () {
        return UDP.HEADER_LENGTH;
    },
    printPorts: function() {
        return (UDP.PORTS[this.sport] || this.sport) + ' ⊳ ' +
               (UDP.PORTS[this.dport] || this.dport);
    },
    toString: function () {
        return this.printPorts();
    }
};

UDP.prototype.printDetails = function () {
    var title = 'User Datagram Protocol';
    var nodes = []
    
    nodes.push(document.createTextNode(
        [
        'Source port: ' + this.sport,
        'Destination port: ' + this.dport,
        'Length: ' + this.len,                    
        'Checksum: 0x' + printNum(this.csum, 16, 4) + ' [' + 
            (this.val ? 'correct' : 'incorrect') + ']'
        ].join('\n')
    ));
    
    return createDetails(title, nodes);
}

UDP.HEADER_LENGTH = 8; // UDP header length in bytes  
UDP.PORTS = []; // well-known ports

if (typeof module !== 'undefined') {
    module.exports.UDP = UDP;
    module.exports.PORTS = UDP.PORTS;
    module.exports.HEADER_LENGTH = UDP.HEADER_LENGTH;
}
