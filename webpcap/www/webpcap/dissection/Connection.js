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
    
    // otherwise prepare structures for gathering content
    this.content = []; // 'unified' buffer for collecting content
    this.srcOrDst = -1; // tells us for which side we are collecting content
    // -1 is undefined, 0 is for source, 1 is for destination
    // also serves as index for the following:
    this.contentBuffer = [[], []]; // buffer for segments to be processed later
    this.seqn = []; // sequence number of next expected segment
}

Connection.prototype = {
    update: function (newPacket) {
        this.packets.push(newPacket);
        this.len += newPacket.orig_len;
    },
    processSegment: _processSegment,
    addSegment: _addSegment,
    addBufferedSegments: _addBufferedSegments,
    bufferSegment: _bufferSegment
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
    
    srcOrDst = (this.dport === tlHeader.dport) | 0;
    
    if (this.srcOrDst === -1) { // we have not collected anything so far
        // init variables
        this.srcOrDst = srcOrDst;
        this.seqn[srcOrDst]      = seqn;
        this.seqn[!srcOrDst | 0] = ackn;
    }
    
    // i.e. this packet is for the side we're collecting for
    if (srcOrDst === this.srcOrDst) {
        // check if there is data from the other side to be processed first
        if (ackn > this.seqn[!srcOrDst | 0]) { // .. there is
            // buffer this segment
            this.bufferSegment(srcOrDst, data, seqn, nextSeqn, offset);
            
            this.srcOrDst = !srcOrDst | 0; // collect for other side now 
            this.addBufferedSegments();
        }
        else { // no data for other side, keep collecting..
            if (seqn === this.seqn[srcOrDst]) { // i.e. next expected segment
                this.addSegment(data, seqn, nextSeqn, offset);
                this.addBufferedSegments();   
            }
            else if (seqn > this.seqn[srcOrDst]) // i.e. will be needed later
                this.bufferSegment(srcOrDst, data, seqn, nextSeqn, offset);
            // else: this is a duplicate
        }        
    }
    else // add this segment to buffer
        this.bufferSegment(srcOrDst, data, seqn, nextSeqn, offset);
}

function _addSegment(data, seqn, nextSeqn, offset) {
    if (seqn === nextSeqn) // no payload, we're done
        return;
    
    var segment; // segment to be collected
    
    segment = new Object();
    segment.data = data;
    segment.offset = offset;
    segment.srcOrDst = this.srcOrDst;
    
    this.content.push(segment);
    this.seqn[this.srcOrDst] = nextSeqn;         
}

function _addBufferedSegments() {    
    var buffer = this.contentBuffer[this.srcOrDst];
    
    while (buffer.length > 0 && buffer[0].seqn === this.seqn[this.srcOrDst]) {
        this.addSegment(buffer[0].data, buffer[0].seqn, buffer[0].nextSeqn,
                        buffer[0].offset);
        
        buffer.shift(); // remove this element
    }   
}

function _bufferSegment(srcOrDst, data, seqn, nextSeqn, offset) {
    if (seqn === nextSeqn) // no payload, we're done
        return;
    
    var buffer; // easier access
    var segment; // segment to be buffered
    var start; // variables for binary search
    var end;
    var middle;
        
    buffer = this.contentBuffer[srcOrDst];
    
    segment = new Object();
    segment.data = data;
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