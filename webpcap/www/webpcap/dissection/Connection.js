function Connection(num, packet, data, offset, parent, tlHeader) {
    this.packets = [packet];        
    this.src = packet.src;
    this.dst = packet.dst;
    this.sport = tlHeader.sport;
    this.dport = tlHeader.dport;
    this.num = num;
    this.len = packet.orig_len;
    this.prot = packet.prot;
    this.visible = 0;
    this.id = tlHeader.id;
    this.info = tlHeader.printPorts();
    
    if (!tlHeader.seqn) // no TCP packet, so we're done here
        return;

    this.contents = [[], []]; // buffers for collecting content
    this.contentBuffer = [[], []]; // buffers for segments to be processed later
    // this.seqn = []; // sequence numbers of next expected segments
}

Connection.prototype = {
    update: function (newPacket) {
        this.packets.push(newPacket);
        this.len += newPacket.orig_len;
    },
    processSegment: _processSegment,
    addSegment: _addSegment,
    addBufferedSegments: _addBufferedSegments,
    bufferSegment: _bufferSegment,
    mergeContent: _mergeContent
};

function _processSegment(packet, data, offset, parent, tlHeader) {
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
    
    ackn = tlHeader.ackn;
    
    srcOrDst = (this.sport === tlHeader.dport) | 0;
    
    if (!this.seqn) { // nothing processed so far, initialize seqns
        this.seqn = [];
        this.seqn[srcOrDst]      = tlHeader.seqn;
        this.seqn[!srcOrDst | 0] = tlHeader.ackn;
    }
        
    if (seqn === this.seqn[srcOrDst]) { // i.e. next expected segment
        this.addSegment(srcOrDst, data, ackn, seqn, nextSeqn, offset);
        this.addBufferedSegments(srcOrDst);
    }
    else if (seqn > this.seqn[srcOrDst]) // i.e. will be needed later
        this.bufferSegment(srcOrDst, data, ackn, seqn, nextSeqn, offset);
    // else: this is a duplicate
}

function _addSegment(srcOrDst, data, ackn, seqn, nextSeqn, offset) {
    if (seqn === nextSeqn) // no payload, we're done
        return;
    
    var segment; // segment to be collected
    
    segment = new Object();
    segment.srcOrDst = srcOrDst;
    segment.data = data;
    segment.ackn = ackn;
    segment.seqn = seqn;
    segment.offset = offset;
    
    this.contents[srcOrDst].push(segment);
    this.seqn[srcOrDst] = nextSeqn;         
}

function _addBufferedSegments(srcOrDst) {    
    var buffer = this.contentBuffer[srcOrDst];
    var s = buffer[0];
    
    while (buffer.length > 0 && s.seqn === this.seqn[srcOrDst]) {
        this.addSegment(srcOrDst, s.data, s.ackn, s.seqn, s.nextSeqn, s.offset);
        buffer.shift(); // remove this element
        s = buffer[0];
    }   
}

function _bufferSegment(srcOrDst, data, ackn, seqn, nextSeqn, offset) {
    if (seqn === nextSeqn) // no payload, we're done
        return;
    
    var buffer; // easier access
    var segment; // segment to be buffered
    var start; // variables for binary search
    var end;
    var middle;
        
    buffer = this.contentBuffer[srcOrDst];
    
    segment = new Object();
    segment.srcOrDst = srcOrDst;
    segment.data = data;
    segment.ackn = ackn;
    segment.seqn = seqn;
    segment.nextSeqn = nextSeqn;
    segment.offset = offset;
    
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
}

function _mergeContent() {
    var srcOrDst;
    var i;
    var mergedContent;
    
    srcOrDst = (this.contents[1].length && 
                (!this.contents[0].length || 
                 this.contents[1][0].ackn === this.contents[0][0].seqn)) | 0;
    i = [0, 0];
    mergedContent = [];
    
    while (i[0] < this.contents[0].length || i[1] < this.contents[1].length) {
        var oldAckn = this.contents[srcOrDst][i[srcOrDst]].ackn;
        
        while (i[srcOrDst] < this.contents[srcOrDst].length 
            && this.contents[srcOrDst][i[srcOrDst]].ackn === oldAckn) {
            mergedContent.push(this.contents[srcOrDst][i[srcOrDst]]);
            i[srcOrDst]++;
        }
        
        srcOrDst = !srcOrDst | 0;
    }
    
    return mergedContent;
}