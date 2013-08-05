if (typeof require !== 'undefined')
    var printNum = require('../formattedOutput').printNum;

/*
 ******************************************************************
 ************************* IPV6 HEADER ****************************
 ******************************************************************
 */

function IPv6h(data, offset) {
    var byteView  = new  Uint8Array(data, offset, IPv6h.HLEN);
    var shortView = new Uint16Array(data, offset, IPv6h.HLEN / 2);
    
    this.v = (byteView[0] & 0xF0) >> 4;            // version
    this.v_tc_fl = byteView.subarray(0, 4);        // version, traffic class, flow label
    this.plen = ntohs(shortView[2]);               // payload length
    this.nh = byteView[6];                         // next header; same as protocol for ipv4h
    this.hlim = byteView[7];                       // hop limit
    this.src = ntohsa(shortView.subarray(4, 12));  // source IPv6 address
    this.dst = ntohsa(shortView.subarray(12, 20)); // destination IPv6 address
        
    this.next_header = null;
}

IPv6h.prototype = {
    getHeaderLength: function () {
        return IPv6h.HLEN;
    },
    printDetails: function (pkt_num, prefix) {
        var details = document.createElement('div');
        details.setAttribute('class','ip');
        var check = document.createElement('input');
        check.setAttribute('type','checkbox');  
        check.setAttribute('id', prefix + 'i6d');
        var hidden = document.createElement('div');
        var label = document.createElement('label');
        var icon = document.createElement('span');
        icon.setAttribute('class', 'dropdown glow');
        label.setAttribute('for', prefix + 'i6d');
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
IPv6h.ALEN = 8;  // IPv6 address length in shorts

// FIXME: check params for consistency
function printIPv6(ip) {
    var output = printNum(ip[0], 16, 2);
    for (i = 1; i < ip.length; i++)
        output += ':' + printNum(ip[i], 16, 0);
    return output;
}

if (typeof module !== 'undefined') {
    module.exports.printIPv6 = printIPv6;
    module.exports.IPv6h = IPv6h;
}
