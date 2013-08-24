'use strict';

if (typeof require !== 'undefined') {
    var readCSVFile = require('../fileio').readCSVFile;
    var printNum = require('../formattedoutput').printNum;
}

function IPv4(littleEndian, packet, dataView, offset, validateChecksums) {    
    this.v    = dataView.getUint8(offset) >> 4; // version
    this.hl   = dataView.getUint8(offset) & 0x0F; // IP header length
    this.tos  = dataView.getUint8(offset + 1); // type of service
    this.tlen = dataView.getUint16(offset + 2, littleEndian); // total length
    this.id   = dataView.getUint16(offset + 4, littleEndian); // identification
    // fragmentation flags & offset
    this.frag = dataView.getUint16(offset + 6, littleEndian); 
    this.frag_off = this.frag & 0x1FFF;
    this.RSVD = this.frag & 0x2000;
    this.DF   = this.frag & 0x4000;
    this.MF   = this.frag & 0x8000;
    
    this.ttl  = dataView.getUint8(offset + 8); // time to live
    this.prot = dataView.getUint8(offset + 9); // protocol (i.e. TCP)
    this.csum = dataView.getUint16(offset + 10, littleEndian);// header checksum
    // source IPv4 address
    this.src  = new DataView(dataView.buffer, offset + 12, 4);
    // destination IPv4 address
    this.dst  = new DataView(dataView.buffer, offset + 16, 4);
    
    /* various options may follow */
    
    this.val = 2; // valid by default, unless...
    if (validateChecksums) {
        this.val = validateChecksum(littleEndian, new DataView(dataView.buffer, 
                        offset, this.getHeaderLength()));
    }
    
    // update the general information
    packet.src = IPv4.printIP(this.src);
    packet.dst = IPv4.printIP(this.dst);
    packet.prot = IPv4.PROTOCOLS[this.prot];
    packet.info = this.toString();
    
    if (!this.val) {
        packet.val = false;
        packet.class = 'malformed';        
    }
            
    this.next_header = null;
}

IPv4.prototype.getHeaderLength = function () {
    return 4 * this.hl;
}

IPv4.prototype.printFlags = function() {
    if (!this.flags)
        return '';
    
    var toReturn = [];
    
    if (this.NS)  toReturn.push('NS');
    if (this.CWR) toReturn.push('CWR');
    if (this.ECE) toReturn.push('ECE');
    if (this.URG) toReturn.push('URG');
    if (this.ACK) toReturn.push('ACK');
    if (this.PSH) toReturn.push('PSH');
    if (this.RST) toReturn.push('RST');
    if (this.SYN) toReturn.push('SYN');
    if (this.FIN) toReturn.push('FIN');
    
    return '[' + toReturn.join(', ') + ']';
}

IPv4.prototype.toString = function () {
    return '';
}

IPv4.prototype.printDetails = function () {
    var title = 'Internet Protocol Version ' + this.v;
    var nodes = []
    
    nodes.push(document.createTextNode(
        [
        'Version: ' + this.v,
        'Header length: ' + this.getHeaderLength(),
        'Differentiated Services Field: 0x' + printNum(this.tos, 16, 2),
        'Total Length: ' + this.tlen,
        'Identification: 0x' + printNum(this.id, 16, 4) + ' (' + this.id + ')',
        // FIXME
        //        = 'Flags: ' + ,
        'Fragment offset: ' + this.off,
        'Time to live: ' + this.ttl,
        'Protocol: ' + IPv4.PROTOCOLS[this.prot] + ' (' + this.prot + ')',
        'Header checksum: 0x' + printNum(this.csum, 16, 4) + 
            IPv4.CHECKSUM_VALUES[this.val],
        'Source: ' + IPv4.printIP(this.src),
        'Destination: ' + IPv4.printIP(this.dst)
        ].join('\n')
    ));
    
    return createDetails(title, nodes);
}

IPv4.MIN_HEADER_LENGTH = 20; // IPv4 minimum header length in bytes 
IPv4.ADDRESS_LENGTH = 4;  // IPv4 address length in bytes
IPv4.PROTOCOLS = readCSVFile(
    'webpcap/dissection/resources/protocol-numbers-1.csv', 0, 1);
// this variable is shared among all checksum-having protocols
IPv4.CHECKSUM_VALUES = [' [incorrect]', ' [correct]', ' [not checked]', 
                        ' [not specified]']; // last entry is for UDP only

IPv4.printIP = function (ip) {
    // check param for consistency
    if (!ip.getUint8)
        throw 'IPv4 address param has to be a DataView object.';
    if (ip.byteLength !== IPv4.ADDRESS_LENGTH)
        console.log('Warning: Incorrect IPv4 address length.');
    
    var ipFragments = [];
    for (var i = 0; i < ip.byteLength; i++)
        ipFragments[i] = ip.getUint8(i);
    return ipFragments.join('.');
}

function validateChecksum(littleEndian, dataView) {    
    var val = 0;
    for (var i = 0; i < dataView.byteLength; i += 2)
        val += dataView.getUint16(i, littleEndian);
    val = ~((val & 0xffff) + (val >>> 16)) & 0xffff;
    
    return val === 0 ? 1 : 0;
}

if (typeof module !== 'undefined') {
    module.exports.printIP = IPv4.printIP;
    module.exports.IPv4 = IPv4;
    module.exports.MIN_HEADER_LENGTH = IPv4.MIN_HEADER_LENGTH;
    module.exports.ADDRESS_LENGTH = IPv4.ADDRESS_LENGTH;
    module.exports.PROTOCOLS = IPv4.PROTOCOLS;
    module.exports.CHECKSUM_VALUES = IPv4.CHECKSUM_VALUES ;
    module.exports.validateChecksum = validateChecksum;
}