var assert = require('assert');
var fs = require('fs');
var md5 = require('MD5');
var Dissector = require('../../dissection/dissector').Dissector;
var readPcapGlobalHeader = require('../../fileio').readPcapGlobalHeader;
var bufferToArrayBuffer = require('../../arraybuffers').bufferToArrayBuffer;
var arrayBufferToBuffer = require('../../arraybuffers').arrayBufferToBuffer;

var PATH = './test/dissection/http_hhucn.pcap';

// these were calculated with wireshark (follow stream -> save as) & md5sum
var md5sums =
[
    'f574a14309b49d4c45735ac4d62e2b80', // source of first connection
    '2f1abe231bb9c0f33dda70ddb893c837', // destination of first connection
    'a723e0a9be5bd6ce2d90c458945d79bd', // source of second connection
    '052e3679c16ee9cccdc8b9aaf0b33136', // and so forth ...
    'e2cc2edb56e0b505a3913cab9e879ae6',
    '99562599430fc44b0ffa3a015c969a27',
    'd41d8cd98f00b204e9800998ecf8427e', // no content for the last two
    'd41d8cd98f00b204e9800998ecf8427e'
]

test('content from http_hhucn.pcap does not include more packets than whole ' + 
     'connection', function () 
{
    var dissector = new Dissector();
    var data = fs.readFileSync(PATH);
    data = bufferToArrayBuffer(data);
    
    readPcapGlobalHeader(data.slice(0, 24), dissector);
    dissector.dissect(data.slice(24));
    
    for (var i = 0; i < dissector.getConnectionsByArrival().length; i++) {
        var conn = dissector.getConnectionsByArrival()[i];
        var srcContent = conn.contents[0];
        var dstContent = conn.contents[1];
        
        var bool = srcContent.length + dstContent.length <= conn.packets.length;
        
        assert.strictEqual(bool, true);
    }
});

test('merged content and source + destination content from http_hhucn.pcap ' +
     'include same number of packets', function () 
{
    var dissector = new Dissector();
    var data = fs.readFileSync(PATH);
    data = bufferToArrayBuffer(data);
    
    readPcapGlobalHeader(data.slice(0, 24), dissector);
    dissector.dissect(data.slice(24));
    
    for (var i = 0; i < dissector.getConnectionsByArrival().length; i++) {
        var conn = dissector.getConnectionsByArrival()[i];
        var srcContent = conn.contents[0];
        var dstContent = conn.contents[1];
        var mergedContent = conn.mergeContent();
        
        assert.strictEqual(srcContent.length + dstContent.length, 
                           mergedContent.length);
    }
});

test('md5 sums of content from http_hhucn.pcap are correct', function () {
    var dissector = new Dissector();
    var data = fs.readFileSync(PATH);
    data = bufferToArrayBuffer(data);
    
    readPcapGlobalHeader(data.slice(0, 24), dissector);
    dissector.dissect(data.slice(24));
        
    for (var i = 0; i < dissector.getConnectionsByArrival().length; i++) {
        var conn = dissector.getConnectionsByArrival()[i];
        var srcContent = arrayBufferToBuffer(conn.getContent(0));
        var dstContent = arrayBufferToBuffer(conn.getContent(1));
        
        assert.strictEqual(md5(srcContent), md5sums[i * 2]);
        assert.strictEqual(md5(dstContent), md5sums[i * 2 + 1]);
    }
});