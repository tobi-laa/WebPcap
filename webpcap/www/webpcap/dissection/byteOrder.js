var switchByteOrder = true; // if false, byte order won't be switched

/**
 * Switches the byte order of a 32-bit integer.
 *
 * @param {number} num Number whose byte order is to be switched
 * @returns {number} Number with switched byte order
 */
function ntohl(num) {
    if (!switchByteOrder) return num;
    return ((num >>>  8)  & 0x0000ff00) | ((num <<  8)  & 0x00ff0000) |
           ((num >>>  24) & 0x000000ff) | ((num <<  24) & 0xff000000);
}

/**
 * Switches the byte order of a 16-bit integer.
 *
 * @param {number} num Number whose byte order is to be switched
 * @returns {number} Number with switched byte order
 */
function ntohs(num) {
    if (!switchByteOrder) return num;
    return ((num >>  8) & 0x00ff) | ((num <<  8) & 0xff00);
}

/**
 * Switches the byte order of a 16-bit integer array.
 *
 * @param {TypedArray} array Numbers whose byte order is to be switched
 * @returns {TypedArray} Numbers with switched byte order
 */
function ntohsa(array) {
    if (!switchByteOrder) return array;
    for (var i = 0; i < array.length; i++)
        array[i] = ntohs(array[i]);
    return array;
}

/**
 * Sets the behavior for byte order switching methods.
 *
 * @param {boolean} bool If true, methods will switch byte order
 */
function setSwitchByteOrder(bool) {
    switchByteOrder = bool;
}

/**
 * Gets the behavior for byte order switching methods.
 *
 * @returns {boolean} bool true if methods switch byte order
 */
function getSwitchByteOrder(bool) {
    return switchByteOrder;
}

if (typeof module !== 'undefined') {
    module.exports.ntohl = ntohl;
    module.exports.ntohs = ntohs;
    module.exports.htonl = ntohl;
    module.exports.htons = ntohs;
    module.exports.setSwitchByteOrder = setSwitchByteOrder;
    module.exports.getSwitchByteOrder = getSwitchByteOrder;
}