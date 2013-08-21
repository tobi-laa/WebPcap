if (typeof require !== 'undefined') {
    var getSwitchByteOrder = require('./byteOrder').getSwitchByteOrder;
    var validateChecksum = require('./IPv4h').validateChecksum;
}
/*
 ******************************************************************
 ************************** TCP HEADER ****************************
 ******************************************************************
 */
var TCP_PORTS = []; // well-known ports
TCP_PORTS[6600] = 'mpd'; // specifying mpd manually

function TCPh(data, offset, parent) {
    var byteView  = new Uint8Array (data, offset, TCPh.HLEN);
    var shortView = new Uint16Array(data, offset, TCPh.HLEN / 2);/
    var intView   = new DataView(data, offset, TCPh.HLEN);
    
    this.sport    = data.getUint16(0, getSwitchByteOrder()); // source port
    this.dport    = data.getUint16(2, getSwitchByteOrder()); // destination port
    this.seqn     = data.getUint32(4, getSwitchByteOrder()); // sequence number
    this.ackn     = data.getUint32(8, getSwitchByteOrder()); // ACK number
    this.off_rsd  = byteView[12] & 0xfe; // data offset, reserved portion
    this.flags    = ntohs(shortView[6]) & 0x1ff; // various flags
    this.wsize    = ntohs(shortView[7]);     // window size
    this.csum     = ntohs(shortView[8]);     // header checksum
    this.urg      = ntohs(shortView[9]);     // urgent pointer
    /* various options may follow */
    
    if (offset + this.getHeaderLength() > data.byteLength)
        this.val = false; // already bogus
    else { // calculate checksum
        var ph = buildPseudoHeader(parent, data, offset);
        this.val = validateChecksum(ph);
    }

    this.id = createID(parent.src, this.sport, parent.dst, this.dport, 't');
    
    this.NS       = this.flags & 0x100;
    this.CWR      = this.flags & 0x080;
    this.ECE      = this.flags & 0x040;
    this.URG      = this.flags & 0x020;
    this.ACK      = this.flags & 0x010;
    this.PSH      = this.flags & 0x008;
    this.RST      = this.flags & 0x004;
    this.SYN      = this.flags & 0x002;
    this.FIN      = this.flags & 0x001;
    
    this.next_header = null;
    byteView = shortView = intView = null;
}

function createID(src, sport, dst, dport, prefix) {
    if (sport === 0 || dport === 0)
        return false;
    var toSort = ['' + sport, '' + dport];
    for (var i = 0; i < src.length; i++) {
        toSort[0] += src[i];
        toSort[1] += dst[i];
    }
    toSort.sort();
    return prefix + toSort[0] + toSort[1];
}

function buildPseudoHeader(parent, data, offset) {
    var len = data.byteLength - offset;
    var packet = new Uint16Array(data, offset, len / 2 | 0);
        
    if (parent.src.length === 4) { // IPv4
        var ph = new ArrayBuffer(12 + len + (len % 2));
        var byteView = new Uint8Array(ph);
        var shortView = new Uint16Array(ph);
        
        for (var i = 0; i < 4; i++) {
            byteView[i]     = parent.src[i];
            byteView[i + 4] = parent.dst[i];
        }
        byteView[8] = 0; // padding
        byteView[9] = parent.prot; // will always be 6
        shortView[5] = ntohs(len); // TCP length
        
        for (var i = 0; i < packet.length; i++) {
            shortView[i + 6] = packet[i];
        }
        if (len % 2)
            byteView[byteView.length - 2] = 
            new Uint8Array(data)[data.byteLength - 1];
        
        return shortView;
    }
    else { // IPv6
        var ph = new ArrayBuffer(40 + len + (len % 2));
        var byteView = new Uint8Array(ph);
        var shortView = new Uint16Array(ph);
        
        for (var i = 0; i < 8; i++) {
            shortView[i]     = ntohs(parent.src[i]);
            shortView[i + 8] = ntohs(parent.dst[i]);
        }        
        shortView[16] = ntohs(len); // length
        shortView[17] = 0;          // length-padding (32 bit)
        
        shortView[18] = 0;          // padding
         byteView[38] = 0;
         byteView[39] = parent.nh   // next header
        
        for (var i = 0; i < packet.length; i++) {
            shortView[i + 20] = packet[i];
        }
        if (len % 2)
            byteView[byteView.length - 2] = 
            new Uint8Array(data)[data.byteLength - 1];
        
        return shortView;
    }
}

TCPh.prototype = {
    getHeaderLength: function () {
        return 4 * (this.off_rsd >>> 4);
    },
    printDetails: function (pkt_num) {
        var details = document.createElement('div');
        details.setAttribute('class','tcp');
        var check = document.createElement('input');
        check.setAttribute('type','checkbox');  
        check.setAttribute('id', 'td');
        var hidden = document.createElement('div');
        var label = document.createElement('label');
        var icon = document.createElement('span');
        icon.setAttribute('class', 'dropdown glow');
        label.setAttribute('for', 'td');
        label.appendChild(icon);
        label.innerHTML += 'Transmission Control Protocol';
        details.appendChild(check);
        details.appendChild(label);   
         
        hidden.innerHTML = 'Source port: ' + this.sport + '</br>'
                         + 'Destination port: ' + this.dport + '</br>'
                         + 'Sequence number: ' + this.seqn + '</br>'
                         + 'Acknowledgment number: ' + this.ackn + '</br>'
                         + 'Header length: ' + this.getHeaderLength() + '</br>'
                         + 'Flags: ' + printNum(this.flags, 16, 3) + ' ' + this.printFlags() + '</br>'
                         + 'Window size value: ' + this.wsize + '</br>'                         
                         + 'Checksum: 0x' + printNum(this.csum, 16, 4) + ' [' + (this.val ? 'correct' : 'incorrect') + ']</br>';
                         // FIXME options
                                 
        details.appendChild(hidden);
        
        return details;
    },
    printPorts: function() {
        return (TCP_PORTS[this.sport] || this.sport) + ' ⊳ ' +
               (TCP_PORTS[this.dport] || this.dport);
    },
    printFlags: function() {
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
    },
    toString: function () {
        return this.printPorts() + ' ' + this.printFlags();
    }
};

TCPh.HLEN = 20; // TCP minimum header length in bytes

if (typeof module !== 'undefined') {
    module.exports.TCPh = TCPh;
    module.exports.createID = createID;
    module.exports.buildPseudoHeader = buildPseudoHeader;
}
