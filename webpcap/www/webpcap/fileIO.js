if (typeof require !== 'undefined') {
    var dissect = require('./dissection/dissection').dissect;
    var switchByteOrder = require('./dissection/byteOrder').switchByteOrder;
}

var createURI, getURL, appendPacketData;
var MAGIC_NUMBER = (0xa1b2c3d4 >>> 0);
var MIMETYPE = 'application/vnd.tcpdump.pcap';

if (typeof window !== 'undefined') {
    if (Blob && window.URL && URL.createObjectURL) {
        getURL = getBlobURL; 
        createURI = createBlobURI;
    }
    else {
        getURL = getDataURL;
        createURI = createDataURI;
        alert('Hi there!\n\
               Your browser does not support Blobs, so I have to make you \
               download your capture session via a data URI.');
    }
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
    // FIXME: Variable
    // intView[5]   = 1;            // Ethernet    
    intView[5]   = 113;          // linux cooked capture
    
    return pcap_global_header;
}

function createDataURI(mimetype, data) {
    return 'data:' + mimetype + ';base64,' + base64ArrayBuffer(data);
}

function getDataURL() {
    return 'data:' + MIMETYPE + ';base64,' + 
           base64ArrayBuffer(createPcapGlobalHeader()) + 
           base64ArrayBuffer(mergeBuffers(getRawPackets()));
}

function createBlobURI(mimetype, data) {
    var blob = new Blob([data], {type: mimetype, size: data.byteLength});
    return URL.createObjectURL(blob);
}

function getBlobURL() {
    var content = appendBuffer(createPcapGlobalHeader(), mergeBuffers(getRawPackets()));
    var blob = new Blob([content], {type: MIMETYPE, size: content.byteLength});
    return URL.createObjectURL(blob);
}

function readPcapFile(file) {
    if (file.size < 24)
        return;
    
    var fr = new FileReader();
    fr.readAsArrayBuffer(file.slice(0, 24));
    fr.onload = function(evt) {readPcapGlobalHeader(evt.target.result);};
    
    var len = file.size - 24;
    var off = 24;
    
    readPcapFilePiece(file, fr, off, len);
}

var CHUNKSIZE = 1024 * 1024;

function readPcapFilePiece(file, fr, off, len) {
    if (len <= 0)
        return;
    
    fr = new FileReader();
    fr.onloadend = function(evt) {
        dissectMessage(evt.target.result);
        readPcapFilePiece(file, fr, off + CHUNKSIZE, len - CHUNKSIZE);
    };
    fr.readAsArrayBuffer(file.slice(off, off + CHUNKSIZE));
}

function readPcapGlobalHeader(data) {
    var magic_number = new Uint32Array(data, 0, 1)[0] >>> 0;
    if (magic_number === ntohl(MAGIC_NUMBER))
        switchByteOrder(false);
    else if (magic_number !== MAGIC_NUMBER) {
        alert('Invalid Magic Number'); // FIXME
        return false;
    }
}

if (typeof module !== 'undefined') {
    module.exports.readPcapFile = readPcapFile;
    module.exports.dissectPcapFile = dissectPcapFile;
}