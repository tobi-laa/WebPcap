var months = ['Jan','Feb','Mar','Apr','May','Jun',
              'Jul','Aug','Sep','Oct','Nov','Dec'];
              
function printNum(num, base, len) {
    if(num === null)
        return "%";
    var hex = num.toString(base);
    var toReturn = "";
    for (var i = 0; i < (len - hex.length); i++)
        toReturn += "0";
    return toReturn + hex;
}

function printDate(date) {
    return months[date.getMonth()] + " " + date.getDate() + ", " + 
           date.getFullYear() + " " + date.getHours() + ":" + 
           date.getMinutes() + ":" + date.getSeconds();
} 

if (typeof module !== 'undefined')
    module.exports.printNum = printNum;