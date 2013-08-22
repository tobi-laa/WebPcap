if (typeof require !== 'undefined')
    var printNum = require('../formattedOutput').printNum;

/*
 ******************************************************************
 ************************* IPV6 HEADER ****************************
 ******************************************************************
 */

function IPv6h(dataView, offset) {    
    this.v = (dataView.getUint8(offset) & 0xF0) >> 4; // version
    // this.v_tc_fl = ;        // version, traffic class, flow label
    this.plen = dataView.getUint16(offset + 4, !getSwitchByteOrder()); // payload length
    this.nh = dataView.getUint8(offset + 6); // next header; same as protocol for ipv4h
    this.hlim = dataView.getUint8(offset + 7); // hop limit
    this.src = new DataView(dataView.buffer, offset + 8, IPv6h.ALEN);  // source IPv6 address
    this.dst = new DataView(dataView.buffer, offset + 24, IPv6h.ALEN); // destination IPv6 address
        
    this.next_header = null;
}

IPv6h.prototype = {
    getHeaderLength: function () {
        return IPv6h.HLEN;
    },
    printDetails: function (pkt_num) {
        var details = document.createElement('div');
        details.setAttribute('class','ip');
        var check = document.createElement('input');
        check.setAttribute('type','checkbox');  
        check.setAttribute('id', 'i6d');
        var hidden = document.createElement('div');
        var label = document.createElement('label');
        var icon = document.createElement('span');
        icon.setAttribute('class', 'dropdown glow');
        label.setAttribute('for', 'i6d');
        label.appendChild(icon);
        label.innerHTML += 'Internet Protocol Version 6';
        details.appendChild(check);
        details.appendChild(label);   
         
        hidden.innerHTML = 'Version: ' + this.v + '</br>'
                         // FIXME traffic class & flow label
                         + 'Payload length: ' + this.plen + '</br>'
                         + 'Next header: ' + this.nh + '</br>'
                         + 'Hop limit ' + this.hlim + '</br>'
                         + 'Source: ' + printIPv6(this.src) + '</br>'
                         + 'Destination: ' + printIPv6(this.dst) + '</br>';

        details.appendChild(hidden);
        
        return details;
    },
    toString: function() {
        return '';
    }
};

IPv6h.HLEN = 40; // IPv6 header length in bytes
IPv6h.ALEN = 16;  // IPv6 address length in bytes

function printIPv6(ip) {
    var start, tempStart;
    var end, tempEnd;
    var ipFragments;
    
    // check param for consistency
    if (!ip.getUint16)
        throw 'IPv6 address param has to be a DataView object.';
    if (ip.byteLength !== IPv6h.ALEN)
        console.log('Warning: Incorrect IPv6 address length.');
    
    // search longest 0 subsequence
    start = tempStart = end = tempEnd = ip.byteLength / 2; //
    
    for (var i = 0; i < ip.byteLength; i += 2) {
        if (ip.getUint16(i, !getSwitchByteOrder()) === 0) {
            tempStart = i;
            while (i < ip.byteLength && ip.getUint16(i, !getSwitchByteOrder()) === 0)
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
        ipFragments.push(ip.getUint16(i, !getSwitchByteOrder()).toString(16));
    }
    if (end > start) {
        if (end === ip.byteLength || start === 0)
            ipFragments.push(':'); // explicitly add when prefix or suffix
        else
            ipFragments.push(''); // induces a double ::
    }
    for (var i = end; i < ip.byteLength; i += 2) {
        ipFragments.push(ip.getUint16(i, !getSwitchByteOrder()).toString(16));        
    }
    
    return ipFragments.join(':');
}

if (typeof module !== 'undefined') {
    module.exports.printIPv6 = printIPv6;
    module.exports.IPv6h = IPv6h;
}
