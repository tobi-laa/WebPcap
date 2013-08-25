'use strict';

if (typeof require !== 'undefined') {
    var readCSVFile = require('../fileio').readCSVFile;
    var createID = require('./tcp').createID;
    var buildPseudoHeader = require('./tcp').buildPseudoHeader;
    var validateChecksum = require('./ipv4').validateChecksum;
    var IPv4 = require('./ipv4').IPv4;
    IPv4.CHECKSUM_VALUES = require('./ipv4').CHECKSUM_VALUES;
}

function UDP(littleEndian, packet, dataView, offset, parent, validateChecksums)
{    
    this.sport = dataView.getUint16(offset, littleEndian); // source port
    this.dport = dataView.getUint16(offset + 2, littleEndian); // destination port
    this.len   = dataView.getUint16(offset + 4, littleEndian); // length of payload incl. UDP header
    this.csum  = dataView.getUint16(offset + 6, littleEndian); // header checksum
    
    this.val = 2; // valid by default unless...
    if (offset + this.getHeaderLength() > dataView.length) { // bogus...
        packet.val = false;
    }
    else if (!this.csum) // UDP checksum is optional...
        this.val = 4; // i.e. not specified
    else if (validateChecksums) {
        var ph = buildPseudoHeader(littleEndian, dataView, offset, parent);
        this.val = validateChecksum(littleEndian, ph);
    }

    // set general information
    packet.class = packet.prot = 'UDP';
    packet.info = this.toString();
    packet.id = createID(parent.src, this.sport, parent.dst, this.dport, 'u');
    
    if (!this.val) {
        packet.val = false;
        packet.class = 'malformed';        
    }
        
    this.next_header = null;
}

UDP.prototype.getHeaderLength = function () {
    return UDP.HEADER_LENGTH;
}

UDP.prototype.printPorts = function() {
    return (UDP.PORT_NAMES[this.sport] || this.sport) + ' ⊳ ' +
            (UDP.PORT_NAMES[this.dport] || this.dport);
}

UDP.prototype.toString = function () {
    return this.printPorts();
}

UDP.prototype.printDetails = function () {
    var title = 'User Datagram Protocol';
    var nodes = []
    
    nodes.push(document.createTextNode(
        [
        'Source port: ' + this.sport,
        'Destination port: ' + this.dport,
        'Length: ' + this.len,                    
        'Checksum: 0x' + printNum(this.csum, 16, 4) + 
            UDP.CHECKSUM_VALUES[this.val]
        ].join('\n')
    ));
    
    return createDetails(title, nodes);
}

UDP.HEADER_LENGTH = 8; // UDP header length in bytes  
UDP.PORT_NAMES = readCSVFile(
    'webpcap/dissection/resources/service-names-port-numbers-udp.csv', 1, 0);
UDP.CHECKSUM_VALUES = IPv4.CHECKSUM_VALUES ;

if (typeof module !== 'undefined') {
    module.exports.UDP = UDP;
    module.exports.PORT_NAMES = UDP.PORT_NAMES;
    module.exports.HEADER_LENGTH = UDP.HEADER_LENGTH;
}
