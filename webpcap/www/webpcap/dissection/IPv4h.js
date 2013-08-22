'use strict';
/*
 ******************************************************************
 ************************* IPV4 HEADER ****************************
 ******************************************************************
 */

function IPv4h(littleEndian, dataView, offset) {    
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

IPv4h.prototype = {
    getHeaderLength: function () {
        return 4 * this.hl;
    },
    printDetails: function (pkt_num) {
        var details = document.createElement('div');
        details.setAttribute('class','ip');
        var check = document.createElement('input');
        check.setAttribute('type','checkbox');  
        check.setAttribute('id', 'i4d');
        var hidden = document.createElement('div');
        var label = document.createElement('label');
        var icon = document.createElement('span');
        icon.setAttribute('class', 'dropdown glow');
        label.setAttribute('for', 'i4d');
        label.appendChild(icon);
        label.innerHTML += 'Internet Protocol Version 4';
        details.appendChild(check);
        details.appendChild(label);   
         
        hidden.innerHTML = 'Version: ' + this.v + '</br>'
                         + 'Header length: ' + this.getHeaderLength() + '</br>'
                         + 'Differentiated Services Field: 0x' + printNum(this.tos, 16, 2) + '</br>'
                         + 'Total Length: ' + this.tlen + '</br>'
                         + 'Identification: 0x' + printNum(this.id, 16, 4) + ' (' + this.id + ')</br>'
                         // FIXME
        //                  += 'Flags: ' +  + '</br>'
                         + 'Fragment offset: ' + this.off + '</br>'
                         + 'Time to live: ' + this.ttl + '</br>'
                         + 'Protocol: ' + this.prot + '</br>'
                         + 'Header checksum: 0x' + printNum(this.csum, 16, 4) + ' [' + (this.val ? 'correct' : 'incorrect') + ']</br>'
                         + 'Source: ' + printIPv4(this.src) + '</br>'
                         + 'Destination: ' + printIPv4(this.dst) + '</br>';

        details.appendChild(hidden);
        
        return details;
    },
    toString: function () {
        return '';
    }
};

IPv4h.HLEN = 20; // IPv4 minimum header length in bytes 
IPv4h.ALEN = 4;  // IPv4 address length in bytes

function printIPv4(ip) {
    // check param for consistency
    if (!ip.getUint8)
        throw 'IPv4 address param has to be a DataView object.';
    if (ip.byteLength !== IPv4h.ALEN)
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
    module.exports.IPv4h = IPv4h;
    module.exports.validateChecksum = validateChecksum;
}