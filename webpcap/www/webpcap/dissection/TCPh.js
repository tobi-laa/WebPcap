/*
 ******************************************************************
 ************************** TCP HEADER ****************************
 ******************************************************************
 */

function TCPh(data, offset, parent) {
    var shortView = new Uint16Array(data, offset, TCPh.HLEN / 2);
    var intView   = new Uint32Array(data, offset, TCPh.HLEN / 4);
    
    this.sport    = ntohs(shortView[0]);     // source port
    this.dport    = ntohs(shortView[1]);     // destination port
    // note: >>> 0 is a trick to convert the number to an unsigned integer
    this.seqn     = ntohl(intView[1]) >>> 0; // sequence number
    this.ackn     = ntohl(intView[2]) >>> 0; // ACK number
    // FIXME: maybe split the following in two chars?
    this.off_flag = shortView[6]; // data offset, reserved portion, flags
    this.wsize    = ntohs(shortView[7]);     // window size
    this.csum     = ntohs(shortView[8]);     // header checksum
    this.urg      = ntohs(shortView[9]);     // urgent pointer
    /* various options may follow */
    
    this.id = createID(parent.src, this.sport, parent.dst, this.dport, 't');
    
    this.next_header = null;
}

function createID(src, sport, dst, dport, prefix) {
    if (sport === 0 || dport === 0)
        return false;
    // FIXME find a more elegant way than strings
    var toSort = ['' + sport, '' + dport];
    for (var i = 0; i < src.length; i++) {
        toSort[0] += src[i];
        toSort[1] += dst[i];
    }
    toSort.sort();
    return prefix + toSort[0] + toSort[1];
}

TCPh.prototype = {
    getHeaderLength: function () {
        return 4 * ((ntohs(this.off_flag)) >> 12);
    },
    printDetails: function (pkt_num, prefix) {
        var details = document.createElement('div');
        details.setAttribute('class','tcp');
        var check = document.createElement('input');
        check.setAttribute('type','checkbox');  
        check.setAttribute('id', prefix + 'td');
        var hidden = document.createElement('div');
        var label = document.createElement('label');
        var icon = document.createElement('span');
        icon.setAttribute('class', 'dropdown glow');
        label.setAttribute('for', prefix + 'td');
        label.appendChild(icon);
        label.innerHTML += 'Transmission Control Protocol';
        details.appendChild(check);
        details.appendChild(label);   
         
        hidden.innerHTML = 'Source port: ' + this.sport + '</br>'
                         + 'Destination port: ' + this.dport + '</br>'
                         + 'Sequence number: ' + this.seqn + '</br>'
                         + 'Acknowledgment number: ' + this.ackn + '</br>'
                         + 'Header length: ' + this.getHeaderLength() + '</br>'
                         // FIXME
                         // + 'Flags: ' +  + '</br>'
                         + 'Window size value: ' + this.wsize + '</br>'                         
                         + 'Checksum: 0x' + printNum(this.csum, 16, 4) + '</br>';
                         // FIXME options
                                 
        details.appendChild(hidden);
        
        return details;
    },
    toString: function () {
        return 'SRC Port: '+this.sport+
              ' DST Port: '+this.dport;
    }
};

TCPh.HLEN = 20; // TCP minimum header length in bytes

if (typeof module !== 'undefined')
    module.exports = TCPh;
