'use strict';

if (typeof require !== 'undefined') {
    var printNum = require('../formattedoutput').printNum;
    var IPv4 = require('./ipv4').IPv4;
    IPv4.PROTOCOLS = require('./ipv4').PROTOCOLS;
}

function IPv6(littleEndian, packet, dataView, offset) {    
    this.v = (dataView.getUint8(offset) & 0xF0) >> 4; // version
    // this.v_tc_fl = ;        // version, traffic class, flow label
    this.plen = dataView.getUint16(offset + 4, littleEndian); // payload length
    this.nh = dataView.getUint8(offset + 6); // next header; same as protocol for ipv4h
    this.hlim = dataView.getUint8(offset + 7); // hop limit
    this.src = new DataView(dataView.buffer, offset + 8, IPv6.ADDRESS_LENGTH);  // source IPv6 address
    this.dst = new DataView(dataView.buffer, offset + 24, IPv6.ADDRESS_LENGTH); // destination IPv6 address
        
    this.littleEndian = littleEndian; // store for IP printing method
    
    // update general information
    packet.src = IPv6.printIP(this.src);
    packet.dst = IPv6.printIP(this.dst);
    packet.prot = IPv6.PROTOCOLS[this.nh];
    
    this.next_header = null;
}

IPv6.prototype.getHeaderLength = function () {
    return IPv6.HEADER_LENGTH;
}

IPv6.prototype.toString = function() {
    return '';
}

IPv6.prototype.printDetails = function () {
    var title = 'Internet Protocol Version ' + this.v;
    var nodes = []
    
    nodes.push(document.createTextNode(
        [
        'Version: ' + this.v,
        // FIXME traffic class & flow label
        'Payload length: ' + this.plen,
        'Next header: ' + this.nh,
        'Hop limit ' + this.hlim,
        'Source: ' + IPv6.printIP(this.src, this.littleEndian),
        'Destination: ' + IPv6.printIP(this.dst, this.littleEndian)
        ].join('\n')
    ));
    
    return createDetails(title, nodes);
}

IPv6.HEADER_LENGTH = 40; // IPv6 header length in bytes
IPv6.ADDRESS_LENGTH = 16;  // IPv6 address length in bytes
IPv6.PROTOCOLS = IPv4.PROTOCOLS;

IPv6.printIP = function (ip, littleEndian) {
    var start, tempStart;
    var end, tempEnd;
    var ipFragments;
    
    // check param for consistency
    if (!ip.getUint16)
        throw 'IPv6 address param has to be a DataView object.';
    if (ip.byteLength !== IPv6.ADDRESS_LENGTH)
        console.log('Warning: Incorrect IPv6 address length.');
    
    // search longest 0 subsequence
    start = tempStart = end = tempEnd = ip.byteLength / 2; //
    
    for (var i = 0; i < ip.byteLength; i += 2) {
        if (ip.getUint16(i, littleEndian) === 0) {
            tempStart = i;
            while (i < ip.byteLength && ip.getUint16(i, littleEndian) === 0)
                i += 2;
            tempEnd = i;
            if (tempEnd - tempStart > end - start) {
                end = tempEnd;
                start = tempStart;
            }
        }
    }
    
    // print IPv6 address
    ipFragments = [];
    for (var i = 0; i < start; i += 2) {
        ipFragments.push(ip.getUint16(i, littleEndian).toString(16));
    }
    if (end > start) {
        if (end === ip.byteLength || start === 0)
            ipFragments.push(':'); // explicitly add when prefix or suffix
        else
            ipFragments.push(''); // induces a double ::
    }
    for (var i = end; i < ip.byteLength; i += 2) {
        ipFragments.push(ip.getUint16(i, littleEndian).toString(16));        
    }
    
    return ipFragments.join(':');
}

if (typeof module !== 'undefined') {
    module.exports.printIP = IPv6.printIP;
    module.exports.IPv6 = IPv6;
    module.exports.HEADER_LENGTH = IPv6.MIN_HEADER_LENGTH;
    module.exports.ADDRESS_LENGTH = IPv6.ADDRESS_LENGTH;
}
