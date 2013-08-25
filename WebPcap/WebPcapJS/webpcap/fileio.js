'use strict';

// >>> 0 is a trick to convert the number to an unsigned value
var MAGIC_NUMBER_BIG_ENDIAN_MS    = (0xa1b2c3d4 >>> 0); // millisecond accuracy
var MAGIC_NUMBER_BIG_ENDIAN_NS    = (0xa1b23c4d >>> 0); // nanosecond accuracy
var MAGIC_NUMBER_LITTLE_ENDIAN_MS = (0xd4c3b2a1 >>> 0);
var MAGIC_NUMBER_LITTLE_ENDIAN_NS = (0x4d3cb2a1 >>> 0);

var PCAP_MIMETYPE = 'application/vnd.tcpdump.pcap';

var CHUNKSIZE = 1024 * 1024; // 1 MiB

var createURI;
var pcapGlobalHeader = null;

function initFileIO() {
    if (typeof window !== 'undefined' && Blob && window.URL && 
        URL.createObjectURL) 
    {
        createURI = createBlobURI;
    }
    else {
        createURI = createDataURI;
        console.log('Warning: Using data URIs to download files (slow!).');        
    }
}

// FIXME: does not work 100% correct, for instance for "quoted" tokens
function readCSVFile(fileURL, numIndex, nameIndex) {
    var req;
    var array = [];
    
    if (typeof window === 'undefined' || !window.XMLHttpRequest) {
        console.log('Warning: Empty array returned (readCSVFile)');
        return array;
    }
    
    req = new XMLHttpRequest();
    req.open('get', fileURL, true);
    req.send();    
    req.onload = function () {
        var lines = this.responseText.split('\n');
        var tokens, index;
        
        for (var i = 0; i < lines.length; i++) {
            tokens = lines[i].split(','); // comma separated
            
            // skip empty lines/comments/and so forth, also duplicate entries
            if (!tokens[nameIndex] || isNaN(index = Number(tokens[numIndex])) ||
                array[index])
            {
                continue;                
            }
            
            array[index] = tokens[nameIndex];
        }
    }
    
    return array;
}

function createDataURI(mimetype, data) {
    return 'data:' + mimetype + ';base64,' + 
            base64ArrayBuffer(mergeBuffers(data));
}

function getPcapURI(dissector) {
    return createURI(PCAP_MIMETYPE, 
                     [pcapGlobalHeader].concat(dissector.getRawPackets()));
}

function createBlobURI(mimetype, data) {
    var size = 0;
    var blob;
    
    for (var i = 0; i < data.length; i++)
        size += data[i].byteLength;
    
    blob = new Blob(data, {type: mimetype, size: size});
        
    return URL.createObjectURL(blob);
}

function readPcapFile(file, dissector) {
    if (file.size < 24)
        throw 'Cannot read pcap file: Less than 24 bytes!'
    
    var fr = new FileReader();
    fr.readAsArrayBuffer(file.slice(0, 24));
    fr.onload = function(evt) {
        readPcapGlobalHeader(evt.target.result, dissector);};
        
    readPcapFilePiece(file.slice(24), fr);
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
        dissector.setNanoSecondAccuracy(false);
        dissector.setLittleEndian(false);
        littleEndian = false;
        break;
    case MAGIC_NUMBER_BIG_ENDIAN_NS:
        dissector.setNanoSecondAccuracy(true);
        dissector.setLittleEndian(false);
        littleEndian = false;
        break;
    case MAGIC_NUMBER_LITTLE_ENDIAN_MS:
        dissector.setNanoSecondAccuracy(false);
        dissector.setLittleEndian(true);
        littleEndian = true;
        break;
    case MAGIC_NUMBER_LITTLE_ENDIAN_NS:
        dissector.setNanoSecondAccuracy(true);
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

if (typeof module !== 'undefined') {
    module.exports.readPcapFile = readPcapFile;
    module.exports.readPcapGlobalHeader = readPcapGlobalHeader;
    module.exports.readCSVFile = readCSVFile;
}