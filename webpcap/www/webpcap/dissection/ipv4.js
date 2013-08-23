'use strict';

function IPv4(littleEndian, dataView, offset) {    
    this.v    = dataView.getUint8(offset) >> 4;    // version
    this.hl   = dataView.getUint8(offset) & 0x0F;  // IP header length
    this.tos  = dataView.getUint8(offset + 1);         // type of service
    this.tlen = dataView.getUint16(offset + 2, littleEndian); // total length
    this.id   = dataView.getUint16(offset + 4, littleEndian);          // identification
    this.frag = dataView.getUint16(offset + 6, littleEndian);         // fragmentation flags & offset
    this.off  = dataView.getUint16(offset + 6, littleEndian) & 0x1FFF; // fragmentation offset
    this.ttl  = dataView.getUint8(offset + 8);                  // time to live
    this.prot = dataView.getUint8(offset + 9);                  // protocol (i.e. TCP)
    this.csum = dataView.getUint16(offset + 10, littleEndian);          // header checksum
    this.src  = new DataView(dataView.buffer, offset + 12, 4);    // source IPv4 address
    this.dst  = new DataView(dataView.buffer, offset + 16, 4);    // destination IPv4 address
    /* various options may follow */
    
    if (offset + this.getHeaderLength() > dataView.byteLength)
        this.val = false;
    else 
        this.val = validateChecksum(littleEndian, new DataView(dataView.buffer, offset, this.getHeaderLength()));
        
    this.next_header = null;
}

IPv4.prototype = {
    getHeaderLength: function () {
        return 4 * this.hl;
    },
    toString: function () {
        return '';
    }
};

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
        'Protocol: ' + this.prot,
        'Header checksum: 0x' + printNum(this.csum, 16, 4) + ' [' + (this.val ? 'correct' : 'incorrect') + ']',
        'Source: ' + printIPv4(this.src),
        'Destination: ' + printIPv4(this.dst)
        ].join('\n')
    ));
    
    return createDetails(title, nodes);
}

IPv4.MIN_HEADER_LENGTH = 20; // IPv4 minimum header length in bytes 
IPv4.ADDRESS_LENGTH = 4;  // IPv4 address length in bytes

function printIPv4(ip) {
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
    
    return val === 0;
}

if (typeof module !== 'undefined') {
    module.exports.printIPv4 = printIPv4;
    module.exports.IPv4 = IPv4;
    module.exports.MIN_HEADER_LENGTH = IPv4.MIN_HEADER_LENGTH;
    module.exports.ADDRESS_LENGTH = IPv4.ADDRESS_LENGTH;
    module.exports.validateChecksum = validateChecksum;
}