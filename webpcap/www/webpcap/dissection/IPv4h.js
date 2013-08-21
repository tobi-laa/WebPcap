/*
 ******************************************************************
 ************************* IPV4 HEADER ****************************
 ******************************************************************
 */

function IPv4h(data, offset) {
    var byteView  = new  Uint8Array(data, offset, IPv4h.HLEN);
    var shortView = new Uint16Array(data, offset, IPv4h.HLEN / 2);
    
    this.v    = byteView[0] >> 4;             // version
    this.hl   = byteView[0] & 0x0F;           // IP header length
    this.tos  = byteView[1];                  // type of service
    this.tlen = ntohs(shortView[1]);          // total length
    this.id   = ntohs(shortView[2]);          // identification
    this.frag = ntohs(shortView[3]);          // fragmentation flags & offset
    this.off  = ntohs(shortView[3]) & 0x1FFF; // fragmentation offset
    this.ttl  = byteView[8];                  // time to live
    this.prot = byteView[9];                  // protocol (i.e. TCP)
    this.csum = ntohs(shortView[5]);          // header checksum
    this.src  = byteView.subarray(12, 16);    // source IPv4 address
    this.dst  = byteView.subarray(16, 20);    // destination IPv4 address
    /* various options may follow */
    
    if (offset + this.getHeaderLength() > data.byteLength)
        this.val = false;
    else 
        this.val = validateChecksum(new Uint16Array(data, offset, 
                                                    this.getHeaderLength() / 2));
        
    this.next_header = null;
    byteView = shortView = null;
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

// FIXME: check params for consistency
function printIPv4(ip) {
    var output = ip[0];
    for (i = 1; i < ip.length; i++)
        output += '.'+ip[i];
    return output;
}

function validateChecksum(shortView) {    
    var val = 0;
    for (var i = 0; i < shortView.length; i++)
        val += shortView[i];
    val = ~((val & 0xffff) + (val >>> 16)) & 0xffff;
    
    return val === 0;
}

if (typeof module !== 'undefined') {
    module.exports.printIPv4 = printIPv4;
    module.exports.IPv4h = IPv4h;
    module.exports.validateChecksum = validateChecksum;
}