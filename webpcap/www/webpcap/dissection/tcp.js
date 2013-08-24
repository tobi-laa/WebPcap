'use strict';

if (typeof require !== 'undefined') {
    var readCSVFile = require('../fileio').readCSVFile;
    var validateChecksum = require('./ipv4').validateChecksum;
    var IPv4 = require('./ipv4').IPv4;
    IPv4.CHECKSUM_VALUES = require('./ipv4').CHECKSUM_VALUES;
}

function TCP(littleEndian, packet, dataView, offset, parent, validateChecksums) 
{    
    this.sport    = dataView.getUint16(offset, littleEndian); // source port
    this.dport    = dataView.getUint16(offset + 2, littleEndian); // destination port
    this.seqn     = dataView.getUint32(offset + 4, littleEndian); // sequence number
    this.ackn     = dataView.getUint32(offset + 8, littleEndian); // ACK number
    this.off_rsd  = dataView.getUint8(offset + 12) & 0xfe; // data offset, reserved portion
    this.flags    = dataView.getUint16(offset + 12, littleEndian) & 0x1ff; // various flags
    
    this.NS       = this.flags & 0x100 && 1;
    this.CWR      = this.flags & 0x080 && 1;
    this.ECE      = this.flags & 0x040 && 1;
    this.URG      = this.flags & 0x020 && 1;
    this.ACK      = this.flags & 0x010 && 1;
    this.PSH      = this.flags & 0x008 && 1;
    this.RST      = this.flags & 0x004 && 1;
    this.SYN      = this.flags & 0x002 && 1;
    this.FIN      = this.flags & 0x001 && 1;
    
    this.wsize    = dataView.getUint16(offset + 14, littleEndian);     // window size
    this.csum     = dataView.getUint16(offset + 16, littleEndian);     // header checksum
    this.urg      = dataView.getUint16(offset + 18, littleEndian);     // urgent pointer
    
    /* various options may follow */
    
    this.val = 2; // valid by default, unless...
    if (offset + this.getHeaderLength() > dataView.byteLength) {// already bogus          
        packet.val = false; 
    }
    else if (validateChecksums) { // calculate checksum
        var ph = buildPseudoHeader(littleEndian, dataView, offset, parent);
        this.val = validateChecksum(littleEndian, ph);
    }

    // set general information
    packet.id = createID(parent.src, this.sport, parent.dst, this.dport, 't');
    packet.class = packet.prot = 'TCP';
    packet.info = this.toString();
    
    if (!this.val) {
        packet.val = false;
        packet.class = 'malformed';        
    }
    // special coloring for... 
    else if (this.RST)
        packet.class = 'RST';        
    else if (this.SYN || this.FIN)
        packet.class = 'SYNFIN';
        
    this.next_header = null;
}

function createID(src, sport, dst, dport, prefix) {
    if (sport === 0 || dport === 0)
        return false;
    var toSort = ['' + sport, '' + dport];
    for (var i = 0; i < src.byteLength; i++) {
        toSort[0] += src.getUint8(i);
        toSort[1] += dst.getUint8(i);
    }
    toSort.sort();
    return prefix + toSort[0] + toSort[1];
}

function buildPseudoHeader(littleEndian, dataView, offset, parent) {
    var len = dataView.byteLength - offset;
        
    if (parent.src.byteLength === 4) { // IPv4
        var pseudoHeaderBuffer = new ArrayBuffer(12 + len + (len % 2));
        var pseudoHeaderView = new DataView(pseudoHeaderBuffer);
        
        for (var i = 0; i < 4; i++) {
            pseudoHeaderView.setUint8(i, parent.src.getUint8(i));
            pseudoHeaderView.setUint8(i + 4, parent.dst.getUint8(i));
        }
        pseudoHeaderView.setUint8(8, 0); // padding
        pseudoHeaderView.setUint8(9, parent.prot); // will always be 4
        pseudoHeaderView.setUint16(10, len, littleEndian); // TCP length
        
        for (var i = 0; i < len; i++) {
            pseudoHeaderView.setUint8(i + 12, dataView.getUint8(offset + i));
        }
        if (len % 2) // add padding
            pseudoHeaderView.setUint8(pseudoHeaderView.byteLength - 1, 0);
        
        return pseudoHeaderView;
    }
    else { // IPv6
        var pseudoHeaderBuffer = new ArrayBuffer(40 + len + (len % 2));
        var pseudoHeaderView = new DataView(pseudoHeaderBuffer);
        
        for (var i = 0; i < 16; i++) {
            pseudoHeaderView.setUint8(i, parent.src.getUint8(i));
            pseudoHeaderView.setUint8(i + 16, parent.dst.getUint8(i));
        }        
        pseudoHeaderView.setUint16(32, len, littleEndian); // length
        pseudoHeaderView.setUint16(34, 0, littleEndian); // length-padding (32 bit)        
        pseudoHeaderView.setUint16(36, 0, littleEndian); // padding
        pseudoHeaderView.setUint8(38, 0);
        pseudoHeaderView.setUint8(39, parent.nh); // next header
        
        for (var i = 0; i < len; i++) {
            pseudoHeaderView.setUint8(i + 40, dataView.getUint8(offset + i));
        }
        if (len % 2) // add padding
            pseudoHeaderView.setUint8(pseudoHeaderView.byteLength - 1, 0);
        
        return pseudoHeaderView;
    }
}

TCP.prototype.getHeaderLength =  function () {
    return 4 * (this.off_rsd >>> 4);
}

TCP.prototype.printPorts = function() {
    return (TCP.PORT_NAMES[this.sport] || this.sport) + ' ⊳ ' +
            (TCP.PORT_NAMES[this.dport] || this.dport);
}

TCP.prototype.printFlags = function() {
    if (!this.flags)
        return '';
    
    var flagNames = [];
    
    if (this.NS)  flagNames.push('NS');
    if (this.CWR) flagNames.push('CWR');
    if (this.ECE) flagNames.push('ECE');
    if (this.URG) flagNames.push('URG');
    if (this.ACK) flagNames.push('ACK');
    if (this.PSH) flagNames.push('PSH');
    if (this.RST) flagNames.push('RST');
    if (this.SYN) flagNames.push('SYN');
    if (this.FIN) flagNames.push('FIN');
    
    return flagNames.join(', ');
}
    
TCP.prototype.toString = function () {
    return this.printPorts() + ' [' + this.printFlags() + ']';
}

TCP.prototype.printDetails = function () {
    var title = 'Transmission Control Protocol';
    var nodes = []
    
    nodes.push(document.createTextNode(
        [
        'Source port: ' + this.sport,
        'Destination port: ' + this.dport,
        'Sequence number: ' + this.seqn,
        'Acknowledgment number: ' + this.ackn,
        'Header length: ' + this.getHeaderLength(),
        'Flags: 0x' + printNum(this.flags, 16, 3) + ' (' + this.printFlags() 
            + ')',
        'Window size value: ' + this.wsize,                         
        'Checksum: 0x' + printNum(this.csum, 16, 4) + 
            TCP.CHECKSUM_VALUES[this.val]
        ].join('\n')
    ));
    
    return createDetails(title, nodes);
}

TCP.MIN_HEADER_LENGTH = 20; // TCP minimum header length in bytes
TCP.PORT_NAMES = readCSVFile(
    'webpcap/dissection/resources/service-names-port-numbers-tcp.csv', 1, 0);
TCP.PORT_NAMES[6600] = 'mpd'; // specifying mpd manually
TCP.CHECKSUM_VALUES = IPv4.CHECKSUM_VALUES ;

if (typeof module !== 'undefined') {
    module.exports.TCP = TCP;
    module.exports.PORT_NAMES = TCP.PORT_NAMES;
    module.exports.MIN_HEADER_LENGTH = TCP.MIN_HEADER_LENGTH;
    module.exports.createID = createID;
    module.exports.buildPseudoHeader = buildPseudoHeader;
}
