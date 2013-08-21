if (typeof require !== 'undefined') {
    var dissect = require('./dissection/dissection').dissect;
    var setLinkLayerType = require('./dissection/dissection').setLinkLayerType;
    var setSwitchByteOrder = require('./dissection/byteOrder').setSwitchByteOrder;
}

var createURI;
var pcapGlobalHeader = null;
var MAGIC_NUMBER_MS = (0xa1b2c3d4 >>> 0);
var MAGIC_NUMBER_NS = (0xa1b23c4d >>> 0);
var SLL = 113;
var ETHERNET = 1;
var PCAP_MIMETYPE = 'application/vnd.tcpdump.pcap';

if (typeof window !== 'undefined') {
    if (Blob && window.URL && URL.createObjectURL) {
        createURI = createBlobURI;
    }
    else {
        createURI = createDataURI;
        alert('Hi there!\n' +
              'Your browser does not support Blobs, so I have to make you ' +
              'download your capture session via a data URI.');
    }
}

function createPcapGlobalHeader() {
    if (pcapGlobalHeader) // always prefer a previously received/read header
        return pcapGlobalHeader;
    // otherwise create one yourself
    var pcap_global_header = new ArrayBuffer(24); // 24 bytes long
    
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
    intView[5]   = 113;          // linux cooked capture
    
    return pcap_global_header;
}

function createDataURI(mimetype, data) {
    return {URI: 'data:' + mimetype + ';base64,' + 
                 base64ArrayBuffer(mergeBuffers(data))};
}

function getPcapURI(dissector) {
    return createURI(PCAP_MIMETYPE, [createPcapGlobalHeader()].concat(
                                                    dissector.getRawPackets()));
}

function createBlobURI(mimetype, data) {
    var size = 0;
    for (var i = 0; i < data.length; i++)
        size += data[i].byteLength;
    
    var blob = new Blob(data, {type: mimetype, size: size});
    
    console.log('Created blob of size ' + blob.size + 'bytes');
    
    return {URI: URL.createObjectURL(blob), blob: blob};
}

function readPcapFile(file, dissector) {
    if (file.size < 24)
        return;
    
    var fr = new FileReader();
    fr.readAsArrayBuffer(file.slice(0, 24));
    fr.onload = function(evt) {
        readPcapGlobalHeader(evt.target.result, dissector);};
        
    readPcapFilePiece(file.slice(24), fr);
}

var CHUNKSIZE = 1024 * 1024; // 1 MiB

function readPcapFilePiece(file, fr) {
    if (file.size <= 0)
        return;
    
    fr = new FileReader();
    fr.onloadend = function(evt) {
        dissectMessage(evt.target.result);
        readPcapFilePiece(file.slice(CHUNKSIZE), fr);
    };
    fr.readAsArrayBuffer(file.slice(0, CHUNKSIZE));
}

function readPcapGlobalHeader(data, dissector) {
    var intView, shortView;
    var magicNumber;
    var versionMajor, versionMinor;
    var network;
        
    pcapGlobalHeader = data.slice(0, 24);
    intView   = new Uint32Array(pcapGlobalHeader);
    shortView = new Uint16Array(pcapGlobalHeader);
    
    magicNumber  =   intView[0] >>> 0;
    versionMajor = shortView[2] >>> 0;
    versionMinor = shortView[3] >>> 0;
    network      =   intView[5] >>> 0;
    dissector.setLinkLayerType(network);
    
    switch (magicNumber) {
    case MAGIC_NUMBER_NS:
    case MAGIC_NUMBER_MS:
        setSwitchByteOrder(true);
        break;
    case ntohl(MAGIC_NUMBER_NS):
    case ntohl(MAGIC_NUMBER_MS):
        setSwitchByteOrder(false);
        break;
    default:
        alert('Invalid Magic Number: 0x' + printNum(magicNumber, 16, 8));
        return -1;
    }
    
    switch (network) {
    case SLL:
        break;
    case ETHERNET:
        break;
    default:
        alert('Unsupported link-layer header type (' + network + ').');
        return -1;
    }
    
    console.log('Read pcap global header, file format ' + 
                'v' + versionMajor + '.' + versionMinor);
    
    return 1;
}

if (typeof module !== 'undefined') {
    module.exports.readPcapFile = readPcapFile;
    module.exports.readPcapGlobalHeader = readPcapGlobalHeader;
}