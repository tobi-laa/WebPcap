var assert = require('assert');
ntohl = require('../../dissection/byteOrder').ntohl;
ntohs = require('../../dissection/byteOrder').ntohs;

test('magic number byte order changed correctly (ntohl)', function () {
    var magic_num_ho = 0xa1b2c3d4 >> 0;
    var magic_num_no = 0xd4c3b2a1 >> 0;
    assert.equal(magic_num_ho, ntohl(magic_num_no));
    assert.equal(magic_num_no, ntohl(magic_num_ho));
});

test('magic number byte order changed correctly (ntohs)', function () {
    var magic_num_ho = 0xd4c3 >> 0;
    var magic_num_no = 0xc3d4 >> 0;
    assert.strictEqual(magic_num_ho, ntohs(magic_num_no));
    assert.strictEqual(magic_num_no, ntohs(magic_num_ho));
});