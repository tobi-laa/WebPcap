'use strict';

if (typeof require !== 'undefined') {
    var dissect = require('./dissection/dissection').dissect;
    var setLinkLayerType = require('./dissection/dissection').setLinkLayerType;
}

// >>> 0 is a trick to convert the number to an unsigned value
var MAGIC_NUMBER_BIG_ENDIAN_MS    = (0xa1b2c3d4 >>> 0); // millisecond accuracy
var MAGIC_NUMBER_BIG_ENDIAN_NS    = (0xa1b23c4d >>> 0); // nanosecond accuracy
var MAGIC_NUMBER_LITTLE_ENDIAN_MS = (0xd4c3b2a1 >>> 0);
var MAGIC_NUMBER_LITTLE_ENDIAN_NS = (0x4d3cb2a1 >>> 0);

var PCAP_MIMETYPE = 'application/vnd.tcpdump.pcap';

var createURI;
var pcapGlobalHeader = null;

function initFileIO() {
    if (typeof window !== 'undefined') {
        if (Blob && window.URL && URL.createObjectURL) {
            createURI = createBlobURI;
        }
        else {
            createURI = createDataURI;
            console.log('Warning: Using data URIs to download files (slow!).');
        }
    }    
}

function createDataURI(mimetype, data) {
    return {URI: 'data:' + mimetype + ';base64,' + 
                 base64ArrayBuffer(mergeBuffers(data))};
}

function getPcapURI(dissector) {
    return createURI(PCAP_MIMETYPE, [pcapGlobalHeader].concat(dissector.getRawPackets()));
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
    var dataView;
    var littleEndian;
    var magicNumber;
    var versionMajor, versionMinor;
    var network;
        
    pcapGlobalHeader = data.slice(0, 24);
    dataView = new DataView(pcapGlobalHeader);
    
    magicNumber  = dataView.getUint32(0, false);
    
    switch (magicNumber) {
    case MAGIC_NUMBER_BIG_ENDIAN_MS:
    case MAGIC_NUMBER_BIG_ENDIAN_NS:
        dissector.setLittleEndian(false);
        littleEndian = false;
        break;
    case MAGIC_NUMBER_LITTLE_ENDIAN_MS:
    case MAGIC_NUMBER_LITTLE_ENDIAN_NS:
        dissector.setLittleEndian(true);
        littleEndian = true;
        break;
    default:
        throw 'Invalid Magic Number: 0x' + printNum(magicNumber, 16, 8);
    }    
    
    versionMajor = dataView.getUint16( 4, littleEndian);
    versionMinor = dataView.getUint16( 6, littleEndian);
    network      = dataView.getUint32(20, littleEndian);

    dissector.setLinkLayerType(network);
}

if (typeof module !== 'undefined') {
    module.exports.readPcapFile = readPcapFile;
    module.exports.readPcapGlobalHeader = readPcapGlobalHeader;
}