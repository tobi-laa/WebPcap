var getURL, appendPacketData, cache, dataURL;
var MAGIC_NUMBER = (0xa1b2c3d4 >>> 0);
var MIMETYPE = 'application/vnd.tcpdump.pcap';

if (Blob && window.URL && URL.createObjectURL) {
    getURL = getBlobURL;
    appendPacketData = appendToBlob;
    cache = createPcapGlobalHeader();    
}
else {
    getURL = getDataURL;
    appendPacketData = appendToDataURL;
    dataURL = 'data:' + MIMETYPE + ';base64,' + 
              base64ArrayBuffer(createPcapGlobalHeader());
    cache = null;
}

function createPcapGlobalHeader() {
    // 24 bytes for the global pcap header
    var pcap_global_header = new ArrayBuffer(24);
    
    // we need to fill it with integers and shorts
    var shortView = new Uint16Array(pcap_global_header);
    var intView   = new Uint32Array(pcap_global_header);

    // fill in values for global header
    intView[0]   = MAGIC_NUMBER; // magic number
    shortView[2] = 2;            // version major
    shortView[3] = 4;            // version minor ~> version 2.4
    intView[2]   = 0;            // diff between local time & UTC
    intView[3]   = 0;            // timestamp accuracy
    intView[4]   = 65535;        // snaplen
    intView[5]   = 1;            // Ethernet    
    
    return pcap_global_header;
}

function appendToDataURL(buff) {
    cache = appendBuffer(cache, buff);
    var len = cache.byteLength;
    len -= (len % 3);
    dataURL += base64ArrayBuffer(cache.slice(0, len));
    cache = cache.slice(len, cache.byteLength);
}

function appendToBlob(buff) {
    cache = appendBuffer(cache, buff);
}

function getDataURL() {
    if (cache != null && cache.byteLength > 0)
        return dataURL + base64ArrayBuffer(cache);
    else
        return dataURL;
}

function getBlobURL() {
    var blob = new Blob([cache], {type: MIMETYPE, size: cache.byteLength});
    return URL.createObjectURL(blob);
}

function readPcapFile(file, f) {
    var fr = new FileReader();
    fr.readAsArrayBuffer(file);
    fr.onload = function() {
        var magic_number = new Uint32Array(fr.result, 0, 1)[0] >>> 0;
        if (magic_number === ntohl(MAGIC_NUMBER))
            switchByteOrder(false);
        else if (magic_number !== MAGIC_NUMBER) {
            alert('Invalid Magic Number'); // FIXME
            return false;
        }
        dissect(fr.result.slice(24), f);
        switchByteOrder(true); // always reset this value
        return true;
    };
}