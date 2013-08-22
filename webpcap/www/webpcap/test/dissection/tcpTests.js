var assert = require('assert');
var TCPh = require('../../dissection/TCPh').TCPh;

// bogus IPv4 header values
var ip = new DataView(new ArrayBuffer(4));
var parent = {src: ip, dst: ip, prot: 0}

var data = new DataView(new Uint8Array(
[
    0x39, 0x05, 0x50, 0x00, // ports 1337 & 80
    0x67, 0x07, 0x00, 0x00, // seqn 1895
    0x7C, 0xD9, 0x01, 0x00, // ackn 121212
    0x35, 0x00, 0x00, 0x02, // urg, ack, rst, fin, winsize 512
    0x15, 0x03, 0x00, 0x04  // checksum 789 (invalid), urg pointer 1024
]).buffer);

test('dissected TCP values from self-made packet are correct', function () {
    var tcp = new TCPh(true, data, 0, parent);
    
    assert.strictEqual(tcp.sport, 1337);
    assert.strictEqual(tcp.dport, 80);
    assert.strictEqual(tcp.seqn, 1895);
    assert.strictEqual(tcp.ackn, 121212);
    assert.strictEqual(tcp.NS, 0);
    assert.strictEqual(tcp.CWR, 0);
    assert.strictEqual(tcp.ECE, 0);
    assert.strictEqual(tcp.URG, 1);
    assert.strictEqual(tcp.ACK, 1);
    assert.strictEqual(tcp.PSH, 0);
    assert.strictEqual(tcp.RST, 1);
    assert.strictEqual(tcp.SYN, 0);
    assert.strictEqual(tcp.FIN, 1);
    assert.strictEqual(tcp.wsize, 512);
    assert.strictEqual(tcp.csum, 789);
    assert.strictEqual(tcp.urg, 1024);
});