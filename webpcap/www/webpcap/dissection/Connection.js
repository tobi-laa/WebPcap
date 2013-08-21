if (typeof require !== 'undefined') {
    var mergeBuffers = require('../arrayBuffers').mergeBuffers;
}

/**
 * Class describing Connection objects. These bundle information for either TCP
 * or UDP connections. All packets with the same ID will be processed by the
 * same Connection object. Also offers methods to extract TCP content.
 * @param {number} num Number of this connection
 * @param {Packet} packet Dissected packet
 * @param {ArrayBuffer} data Raw packet
 * @param {TCPh|UDPh} tlHeader Transport layer header of packet
 * @constructor
 */
function Connection(num, packet, data, tlHeader) {
    this.num = num;
    this.id = packet.id;    
    this.packets = [packet];        
    this.src = packet.src;
    this.dst = packet.dst;
    this.sport = tlHeader.sport;
    this.dport = tlHeader.dport;
    this.len = packet.orig_len;
    this.prot = packet.prot;
    this.visible = 0;
    this.info = tlHeader.printPorts();
    
    if (!tlHeader.seqn) // no TCP packet, so we're done here
        return;

    this.contents = [[], []]; // buffers for collecting content
    this.contentBuffer = [[], []]; // buffers for segments to be processed later
    // this.seqn = []; // sequence numbers of next expected segments
}

Connection.prototype.update = function (newPacket) {
    this.packets.push(newPacket);
    this.len += newPacket.orig_len;
};

Connection.prototype.processSegment = function (packet, data, offset, parent, tlHeader) {
    if (tlHeader.SYN) // skip syn packages; there's no payload
        return;
    
    var seqn;     // current sequence number and next sequence number
    var nextSeqn;
    var ackn;     // current ack number
    var srcOrDst; // 0 if the packet belongs to the source side; 1 otherwise
    
    seqn = nextSeqn = tlHeader.seqn;
    // calculate nextSeqn....
    if (parent.tlen) // IPv4, total length
        nextSeqn += parent.tlen - tlHeader.getHeaderLength() - parent.getHeaderLength();
    else if (parent.plen) // IPv6, payload length
        nextSeqn += parent.plen - tlHeader.getHeaderLength();
    else // as a last resort, calculate it like this
        nextSeqn += packet.orig_len + Pcaph.HLEN - offset;
    
    if (seqn === nextSeqn) // no payload, we're done
        return;
    
    ackn = tlHeader.ackn;
    
    srcOrDst = (this.sport === tlHeader.dport) | 0;
    
    if (!this.seqn) { // nothing processed so far, initialize seqns
        this.seqn = [];
        this.seqn[srcOrDst]      = tlHeader.seqn;
        this.seqn[!srcOrDst | 0] = tlHeader.ackn;
        this.srcOrDst = srcOrDst;
    }
        
    if (seqn === this.seqn[srcOrDst]) { // i.e. next expected segment
        this.addSegment(srcOrDst, data, ackn, seqn, nextSeqn, offset);
        this.addBufferedSegments(srcOrDst);
    }
    else if (seqn > this.seqn[srcOrDst]) // i.e. will be needed later
        this.bufferSegment(srcOrDst, data, ackn, seqn, nextSeqn, offset);
    // else: this is a duplicate
}

Connection.prototype.addSegment = function (srcOrDst, data, ackn, seqn, nextSeqn, offset) {    
    var segment; // segment to be collected
    
    segment = {
        srcOrDst: srcOrDst,
        data: data,
        ackn: ackn,
        seqn: seqn,
        offset: offset
    };
    
    this.contents[srcOrDst].push(segment);
    this.seqn[srcOrDst] = nextSeqn;         
}

Connection.prototype.addBufferedSegments = function (srcOrDst) {    
    var buffer = this.contentBuffer[srcOrDst];
    var s = buffer[0];
    
    while (buffer.length > 0 && s.seqn === this.seqn[srcOrDst]) {
        this.addSegment(srcOrDst, s.data, s.ackn, s.seqn, s.nextSeqn, s.offset);
        buffer.shift(); // remove this element
        s = buffer[0];
    }   
}

Connection.prototype.bufferSegment = function (srcOrDst, data, ackn, seqn, nextSeqn, offset) {    
    var buffer; // easier access
    var segment; // segment to be buffered
    var start; // variables for binary search
    var end;
    var middle;
        
    buffer = this.contentBuffer[srcOrDst];
    
    segment = {
        srcOrDst: srcOrDst,
        data: data,
        ackn: ackn,
        seqn: seqn,
        nextSeqn: nextSeqn,
        offset: offset
    };
    
    // seek the position at which data should be inserted (binary search)
    start = 0;
    end = buffer.length - 1;
    
    if (end < 0) { // i.e. empty buffer
        buffer[0] = segment;
        return;            
    }
    
    while (start < end) {
        middle = ((start + end) / 2) | 0;
        if (buffer[middle].seqn < seqn)
            start = middle + 1;
        else
            end = middle;
    }
    
    if (buffer[start].seqn < seqn)
        buffer.splice(start + 1, 0, segment);
    else if (buffer[start].seqn > seqn)
        buffer.splice(start, 0, segment);
    // else: this is a duplicate
    
    if (buffer.length > 20) // keep the buffer small
        buffer.shift();
}

Connection.prototype.getContent = function (srcOrDst) {
    var data = [];
    
    for (var i = 0; i < this.contents[srcOrDst].length; i++)
        data[i] = this.contents[srcOrDst][i].data.slice(
                    this.contents[srcOrDst][i].offset);
    
    return mergeBuffers(data);
}

Connection.prototype.mergeContent = function () {
    var srcOrDst;
    var i;
    var mergedContent;
    
    srcOrDst = this.srcOrDst;
    i = [0, 0];
    mergedContent = [];
    
    while (i[0] < this.contents[0].length && i[1] < this.contents[1].length) {        
        var oldAckn = this.contents[srcOrDst][i[srcOrDst]].ackn;
        
        while (i[srcOrDst] < this.contents[srcOrDst].length 
            && this.contents[srcOrDst][i[srcOrDst]].ackn === oldAckn) {
            mergedContent.push(this.contents[srcOrDst][i[srcOrDst]]);
            i[srcOrDst]++;
        }
        
        srcOrDst = !srcOrDst | 0;
    }
    while (i[0] < this.contents[0].length) {
        mergedContent.push(this.contents[0][i[0]]);
        i[0]++;
    }
    while (i[1] < this.contents[1].length) {
        mergedContent.push(this.contents[1][i[1]]);
        i[1]++;
    }
    
    return mergedContent;
}

if (typeof module !== 'undefined') {
    module.exports.Connection = Connection;
}