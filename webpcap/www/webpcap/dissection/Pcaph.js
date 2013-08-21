/*
 ******************************************************************
 ************************* PCAP HEADER ****************************
 ******************************************************************
 */

function Pcaph(data, offset) {
    var intView  = new Uint32Array(data, offset, Pcaph.HLEN / 4);
    
    this.ts_sec   = intView[0];  // timestamp seconds
    this.ts_usec  = intView[1];  // timestamp microseconds
    this.incl_len = intView[2];  // number of octets of packet saved in file
    this.orig_len = intView[3];  // actual length of packet
    
    // some general information about the packet (not part of pcap header)
    this.num;
    this.src;
    this.dst;
    this.prot;
    this.class;
    this.id;
    
    this.next_header = null;
    intView = shortView = null;
}

Pcaph.prototype = {
    getHeaderLength: function () {
        return Pcaph.HLEN;
    },
    printDetails: function (pkt_num) {
        var details = document.createElement('div');
        details.setAttribute('class','pcap');
        var check = document.createElement('input');
        check.setAttribute('type','checkbox');  
        check.setAttribute('id', 'pd');
        var hidden = document.createElement('div');
        var label = document.createElement('label');
        var icon = document.createElement('span');
        icon.setAttribute('class', 'dropdown glow');
        label.setAttribute('for', 'pd');
        label.appendChild(icon);
        label.innerHTML += 'General Information';
        details.appendChild(check);
        details.appendChild(label);        
        
        hidden.innerHTML += 'Arrival Time: ' + this.printTime() + '</br>';
        hidden.innerHTML += 'Frame Length: ' + this.incl_len + ' bytes (' + (this.incl_len * 8) + ' bits)</br>';
        hidden.innerHTML += 'Captured Length: ' + this.orig_len + ' bytes (' + (this.orig_len * 8) + ' bits)</br>';
        
        details.appendChild(hidden);
        
        return details;
    },
    printTime: function () {
        return printDate(new Date(this.ts_sec * 1000)) + '.' + printNum(this.ts_usec, 10, 6);
    },
    toString: function () {
        return '';
    }
};

Pcaph.HLEN = 16; // pcap header length in bytes 

if (typeof module !== 'undefined') {
    module.exports.Pcaph = Pcaph;
}