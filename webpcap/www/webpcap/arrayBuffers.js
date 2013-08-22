'use strict';

function mergeBuffers(buffers) {
    var byteLength = 0, currentPos = 0;
    var mergedBuffer;
    var byteView;
    
    for (var i = 0; i < buffers.length; i++) {
        if (buffers[i]) // handle null or undefined as empty buffers
            byteLength += buffers[i].byteLength;
    }
    
    mergedBuffer = new ArrayBuffer(byteLength);
    byteView = new Uint8Array(mergedBuffer);
    
    for (var i = 0; i < buffers.length; i++) {
        if (buffers[i]) {
            byteView.set(new Uint8Array(buffers[i]), currentPos);
            currentPos += buffers[i].byteLength;
        }
    }
    
    return mergedBuffer;
}

// deprecated method
function appendBuffer(fstBuff, sndBuff) {
    mergeBuffers([fstBuff, sndBuff]);
} 

// Credit for the method below goes to Jon Leighton.
// See: https://gist.github.com/jonleighton/958841
//
// This method will be replaced by
//
// function base64ArrayBuffer(arrayBuffer) {
//     return window.btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)));
// }
//
// unless a proper license can be provided.
//
// Converts an ArrayBuffer directly to base64, without any intermediate 'convert to string then
// use window.btoa' step. According to my tests, this appears to be a faster approach:
// http://jsperf.com/encoding-xhr-image-data/5

function base64ArrayBuffer(arrayBuffer) {
  var base64    = ''
  var encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

  var bytes         = new Uint8Array(arrayBuffer)
  var byteLength    = bytes.byteLength
  var byteRemainder = byteLength % 3
  var mainLength    = byteLength - byteRemainder

  var a, b, c, d
  var chunk

  // Main loop deals with bytes in chunks of 3
  for (var i = 0; i < mainLength; i = i + 3) {
    // Combine the three bytes into a single integer
    chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]

    // Use bitmasks to extract 6-bit segments from the triplet
    a = (chunk & 16515072) >> 18 // 16515072 = (2^6 - 1) << 18
    b = (chunk & 258048)   >> 12 // 258048   = (2^6 - 1) << 12
    c = (chunk & 4032)     >>  6 // 4032     = (2^6 - 1) << 6
    d = chunk & 63               // 63       = 2^6 - 1

    // Convert the raw binary segments to the appropriate ASCII encoding
    base64 += encodings[a] + encodings[b] + encodings[c] + encodings[d]
  }

  // Deal with the remaining bytes and padding
  if (byteRemainder == 1) {
    chunk = bytes[mainLength]

    a = (chunk & 252) >> 2 // 252 = (2^6 - 1) << 2

    // Set the 4 least significant bits to zero
    b = (chunk & 3)   << 4 // 3   = 2^2 - 1

    base64 += encodings[a] + encodings[b] + '=='
  } else if (byteRemainder == 2) {
    chunk = (bytes[mainLength] << 8) | bytes[mainLength + 1]

    a = (chunk & 64512) >> 10 // 64512 = (2^6 - 1) << 10
    b = (chunk & 1008)  >>  4 // 1008  = (2^6 - 1) << 4

    // Set the 2 least significant bits to zero
    c = (chunk & 15)    <<  2 // 15    = 2^4 - 1

    base64 += encodings[a] + encodings[b] + encodings[c] + '='
  }
  
  return base64
}

// convert between nodejs's buffers and arrayBuffers

function bufferToArrayBuffer(buff) {
    var newBuff = new ArrayBuffer(buff.length);
    var byteView = new Uint8Array(newBuff);
    
    for (var i = 0; i < buff.length; i++) {
        byteView[i] = buff[i];
    }
    return newBuff;
} 

function arrayBufferToBuffer(arrBuff) {
    var newBuff = new Buffer(arrBuff.byteLength);
    var byteView = new Uint8Array(arrBuff);
    
    for (var i = 0; i < arrBuff.byteLength; i++) {
        newBuff[i] = byteView[i];
    }
    return newBuff;
}

if (typeof module !== 'undefined') {
    module.exports.appendBuffer = appendBuffer;
    module.exports.mergeBuffers = mergeBuffers;
    module.exports.base64ArrayBuffer = base64ArrayBuffer;
    module.exports.bufferToArrayBuffer = bufferToArrayBuffer;
    module.exports.arrayBufferToBuffer = arrayBufferToBuffer;
}