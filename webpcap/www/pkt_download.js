var cache = null;

var data_url = "data:application/x-download;base64,";
data_url    += base64ArrayBuffer(createPcapGlobalHeader());

var tmpLink = document.createElement("a");
tmpLink.download = "log.pcap";

function createPcapGlobalHeader() {
    // 24 bytes for the global pcap header
    var pcap_global_header = new ArrayBuffer(24);
    
    // we need to fill it with integers and shorts
    var shortView = new Uint16Array(pcap_global_header);
    var intView   = new Uint32Array(pcap_global_header);

    // fill in values for global header
    intView[0]   = 0xa1b2c3d4; // magic number
    shortView[2] = 2;          // version major
    shortView[3] = 4;          // version minor ~> version 2.4
    intView[2]   = 0;          // diff between local time & UTC
    intView[3]   = 0;          // timestamp accuracy
    intView[4]   = 65535;      // snaplen
    intView[5]   = 1;          // Ethernet    
    
    return pcap_global_header;
}

function saveCapture() {
    if (cache != null && cache.byteLength > 0)
        tmpLink.href = data_url + base64ArrayBuffer(cache);
    else
        tmpLink.href = data_url;
    tmpLink.click();
}

function appendToDataUrl(buff) {
    cache = appendBuffer(cache, buff);
    var len = cache.byteLength;
    len -= (len % 3);
    data_url += base64ArrayBuffer(cache.slice(0, len));
    cache = cache.slice(len, cache.byteLength);
}

function appendBuffer(buff, toAppend) {
    if (buff == null)
        return toAppend;
    if (toAppend == null)
        return buff;
    var toReturn = new Uint8Array(buff.byteLength + toAppend.byteLength);
    toReturn.set(new Uint8Array(buff),     0);
    toReturn.set(new Uint8Array(toAppend), buff.byteLength);
    return toReturn.buffer;
}