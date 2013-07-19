var doc = document;
var pktoutput = doc.getElementById('output');
var pkttable  = pktoutput.getElementsByTagName('div')[0];
var pktdetails = doc.getElementById('details');
var pktpayload = doc.getElementById('raw');

var selectedPacketRow = new Object();
var selectedConnectionRow = new Object();

var ws_url = 'ws://' + window.location.host + '/binary';
var ws = null;  
var conn_button = doc.getElementById('conn');

var MINSCROLLBARSIZE = 28;
var MAXSCROLLBARSTART;
var currentRow = 0;
var rows = [];

var packetView = true;
var connRows = {};

var contextMenu = doc.getElementById('contextmenu');

var anim;

var autoscroll = true;

var pkts = getDissectedPackets();
var scrollanchor = 0;

var conns = getConnectionsByArrival();
var connAnchor = 0;
var pktAnchor = -1;

var shownPackets = 0;

var scrollbox = doc.getElementById('scrollbox');
var scrollbar = doc.getElementById('scrollbar');

var maxPackets = 0;

var renderNextTime = false;

var filter = false;

var scrollup = doc.getElementById('scrollup');
var scrolldown = doc.getElementById('scrolldown');

var scrollbarSelected = false;

var dontDraw = false;

function onWSMessage(msg) {
    var oldLength, length, anchor;
    
    if (packetView) oldLength = pkts.length;
    else            oldLength = connectionViewLength()[0];
    
    dissect(msg.data);
    // simpleDissect(msg.data, simplePrint);
    
    if (packetView)
        length = pkts.length;
    else {
        var tuple = connectionViewLength();
        length = tuple[0];
        anchor = tuple[1];   
    }
    
    if (oldLength === length)
        return;
//     if (oldLength < maxPackets)
//         renderNextTime = true;
    if (autoscroll) {
        if (packetView) {
            // we don't want a negative scrollanchor     
            scrollanchor = Math.max(0, pkts.length - maxPackets);
            renderNextTime = true;
        }
        else {
            connectionViewSeek(Math.max(0, length - anchor - maxPackets));
            renderNextTime = true;
        }
    }
    else if (!packetView)
        renderNextTime = true;
}  

function onWSOpen() {
    ws.send('none\0'); // default filter
    conn_button.setAttribute('title', 'Stop the running live capture');
    conn_button.innerHTML =
    '<img class="glow buttonicon" src="img/media-playback-stop.svgz" alt="Start capture">';
}

function onWSClose() {
    ws = null;
    conn_button.setAttribute('title', 'Start a new live capture');
    conn_button.innerHTML =
    '<img class="glow buttonicon" src="img/media-record.svgz" alt="Start capture">';
}

processResize();

function processResize() {
    doc.body.style.fontSize = '1vw';
    
    pktoutput.style.width = '100%';
    scrollbox.style.height = '100%';
    tableheader.style.width = '100%';
    
    tableheader.style.width = (tableheader.offsetWidth - 15) + 'px';
    pktoutput.style.width = (pktoutput.offsetWidth - 15) + 'px';
    scrollbox.style.height = (scrollbox.offsetHeight - 30) + 'px';
    
    MAXSCROLLBARSTART = scrollbox.offsetHeight - MINSCROLLBARSIZE;
    
    maxPackets = 0;
    pkttable.innerHTML = '';
    
    while (pktoutput.scrollHeight <= pktoutput.clientHeight) {
        var row = doc.createElement('div');
        var col = doc.createElement('div');
        row.setAttribute('class','row');        
        col.setAttribute('class', 'col 5p');
        col.innerHTML = 'test';
        row.appendChild(col);
        pkttable.appendChild(row);
        maxPackets++;
    }
    
    pkttable.innerHTML = '';
    renderNextTime = true;    
}

function switchView() {
    packetView = !packetView;
    renderNextTime = true;
}

var tmpLink = document.createElement('a');
tmpLink.download = 'log.pcap';

// will be used to click on the link
var mc = document.createEvent('MouseEvents');
mc.initEvent('click', true, false);

function saveCapture() {
    tmpLink.href = getURL();
    tmpLink.dispatchEvent(mc);
} 

function clickOnFileInput() {
    fileInput.click();
}

// FIXME: performance test
function simplePrint(infos) {
    var row = doc.createElement('div');
    var num   = doc.createElement('div');
    var src  = doc.createElement('div');
    var dst  = doc.createElement('div');
    var prot = doc.createElement('div');
    var len  = doc.createElement('div');
    var info = doc.createElement('div');
        
    row.setAttribute('onclick','processClick(this, ' + infos[0] + ')');
    row.setAttribute('class','row ' + infos[3]);
        
    num.setAttribute('class', 'col 5p tr');    
    src.setAttribute('class', 'col 25p');    
    dst.setAttribute('class', 'col 25p');    
    prot.setAttribute('class', 'col 10p');    
    len.setAttribute('class', 'col 5p');    
    info.setAttribute('class', 'col 30p');
    
    num.innerHTML  = infos[0];
    len.innerHTML  = infos[4];
    src.innerHTML  = infos[1];
    dst.innerHTML  = infos[2];
    prot.innerHTML = infos[3];
    info.innerHTML = infos[5];
    
    row.appendChild(num);
    row.appendChild(src);
    row.appendChild(dst);
    row.appendChild(prot);
    row.appendChild(len);
    row.appendChild(info);
        
    rows[currentRow + MAXROWS] = row;
    currentRow++;
    
    return row;
}

function printRow(packet, customClass) {   
    var row = doc.createElement('div');
    var num   = doc.createElement('div');
    var src  = doc.createElement('div');
    var dst  = doc.createElement('div');
    var prot = doc.createElement('div');
    var len  = doc.createElement('div');
    var info = doc.createElement('div');
        
    row.setAttribute('onclick','processClick(this, ' + packet.num + ')');
    if (packet.id)
        row.setAttribute('oncontextmenu','processRightClick(this, ' + packet.num + ', event, "' + packet.id + '")');
    else
        row.setAttribute('oncontextmenu','processRightClick(this, ' + packet.num + ', event)');
    row.setAttribute('class','row ' + (packet.class || packet.prot));
    
    if (customClass) {
        row.className += ' ' + customClass;
    }
        
    num.setAttribute('class', 'col 10p tr');    
    src.setAttribute('class', 'col 20p'); 
    dst.setAttribute('class', 'col 20p'); 
    prot.setAttribute('class', 'col 10p');    
    len.setAttribute('class', 'col 10p tr');    
    info.setAttribute('class', 'col 30p');
    
    num.innerHTML  = packet.num;
    len.innerHTML  = packet.orig_len;
    src.innerHTML  = packet.src;
    dst.innerHTML  = packet.dst;
    prot.innerHTML = packet.prot;
    
    while (packet.next_header) packet = packet.next_header;
    
    info.innerHTML = packet;
    
    row.appendChild(num);
    row.appendChild(src);
    row.appendChild(dst);
    row.appendChild(prot);
    row.appendChild(len);
    row.appendChild(info);                     
    
    rows[currentRow] = row;
    currentRow++;
    
    return row;
}



function connectionViewLength() {
    var length = 0;
    var anchor = 0;
    
    for (var i = 0; i < conns.length; i ++) {
        if (i === connAnchor)
            anchor = connAnchor + length + pktAnchor + 1;
        length += conns[i].packets.length * conns[i].visible;            
    } 
    length += conns.length;
    
    return [length, anchor];
}

function calculateScrollbarSize() {
    var packetNumber = 0;
    var scrollboxStart;
    var scrollboxSize;
    
    if (packetView) {
        packetNumber = pkts.length;
        scrollboxStart = scrollanchor;
    }
    else {
        var array = connectionViewLength();
        packetNumber = array[0];
        scrollboxStart = array[1];
    }
    
    scrollboxStart = Math.min(scrollboxStart * scrollbox.offsetHeight / packetNumber, MAXSCROLLBARSTART);
    scrollboxSize = Math.max(maxPackets * scrollbox.offsetHeight / packetNumber, MINSCROLLBARSIZE);
    
    if (scrollboxSize >= scrollbox.offsetHeight || packetNumber === 0) {
        scrollbar.className = 'hidden';
        scrollup.className = 'scrollupinactive';
        scrolldown.className = 'scrolldowninactive';
        return;
    }
        
    if (autoscroll) {
        scrollup.className = 'scrollup';
        scrolldown.className = 'scrolldowninactive';
    }
    else {
        scrolldown.className = 'scrolldown';
        // FIXME
        if ((packetView && scrollanchor === 0) || (!packetView && connAnchor === 0 && pktAnchor === -1))
            scrollup.className = 'scrollupinactive';
        else
            scrollup.className = 'scrollup';
    }
    scrollbar.className = '';
    scrollbar.style.height = scrollboxSize + 'px';
    scrollbar.style.top = scrollboxStart + 'px';
}

function selectScrollbox() {
    scrollbarSelected = true;
    doc.body.className = 'suppressselection'; // so we don't select text
    return false;
}

function deselectScrollbox() {
    scrollbarSelected = false;
    doc.body.className = ''; // re-enable (text) selection
    return false;
}

function moveScrollbox(event) {
    if (!scrollbarSelected)
        return true;
    
    autoscroll = false;
    var newPos = (event.pageY - doc.getElementById('scrollcontainer').offsetTop - 15)
                    / scrollbox.offsetHeight;
    
    if (packetView) {
        newPos = (pkts.length * newPos) | 0;
        
        if (newPos < 0)
            newPos = 0;
        else if (newPos >= pkts.length - maxPackets) {
            newPos = pkts.length - maxPackets;
            autoscroll = true;
        }
        
        scrollanchor = newPos;
        renderNextTime = true;
    }
    
    else { // FIXME FIXME FIXME
        var length = 0;
        
        for (var i = 0; i < conns.length; i ++) {
            length += conns[i].packets.length * conns[i].visible;            
        } 
        length += conns.length;
    
        newPos = (length * newPos) | 0;

        if (dontDraw)
            return;
        
        dontDraw = true;
        
        setTimeout(function (){
            dontDraw = false;
            connAnchor = 0;
            pktAnchor = -1;        
            scrollConnectionView(newPos);
        }, 20);  
    }
        
  
}

// FIXME
// setInterval(render, 200);
requestAnimationFrame(render);

function processClick(row, num) {
    selectRow(row, num);
    
    if (packetView) {
        printPacketDetails(num);
        printPayload(num);
        return;
    }
    
    if (getConnectionById(num)) {
        printConnectionDetails(num);
        return;
    }
    
    printPacketDetails(num);
    printPayload(num);
}

function processRightClick(row, num, event, id) {
    processClick(row, num);
    
    if (!id)
        return false;
    
    contextMenu.className = '';
    contextMenu.innerHTML = '';
    contextMenu.style.left = event.pageX + 'px';
    contextMenu.style.top = event.pageY + 'px';
    
    var follow = document.createElement('span');
    follow.setAttribute('onclick','followStream("' + id + '")');
    follow.setAttribute('class', 'contextentry');
    
    if (filter === id)
        follow.innerHTML = 'Unfollow';
    else
        follow.innerHTML = 'Follow this stream';
    
    contextMenu.appendChild(follow);
        
    return false;
}

function render() {    
    if (packetView)
        renderPacketView();
    else {
        renderConnectionView();        
    }
    calculateScrollbarSize();
    
    requestAnimationFrame(render);
}

function renderPacketView() {    
    if (pkts.length === 0 || !renderNextTime)
        return;
    
    pkttable.innerHTML = '';
    
    for (var i = scrollanchor; i <= scrollanchor + maxPackets; i++) {
        if (i >= pkts.length)
            break;
        row = printRow(pkts[i]);
        pkttable.appendChild(row);
        if (pkts[i].num === selectedPacketRow.num)
            selectRow(row, pkts[i].num);
    }
    
    if (autoscroll)
        pktoutput.scrollTop = pktoutput.scrollHeight;
    else
        pktoutput.scrollTop = 0;
    
    renderNextTime = false;
}

function closeContextMenu() {
    contextMenu.className = 'hidden';
}

function printConnectionDetails(id) {
    var conn = getConnectionById(id);
    
    if (!conn)
        return;
    
    var lastPacket = conn.packets[conn.packets.length - 1];    
    
    pktdetails.innerHTML = '';
        
    pktdetails.innerHTML  = 'Last packet arrival: ' + lastPacket.printTime() + '</br>';
    pktdetails.innerHTML += 'Number of pkts: ' + conn.num + '</br>';
    pktdetails.innerHTML += 'Amount of data: ' + printSize(conn.len) + '</br>';
}

function selectRow(row, num) {
    var selectedRow;
    if (packetView)
        selectedRow = selectedPacketRow;
    else
        selectedRow = selectedConnectionRow;
    
    if (selectedRow.row)
        selectedRow.row.setAttribute('class', selectedRow.class);
    selectedRow.class = row.className;    
    selectedRow.row = row;
    selectedRow.num = num;
    
    row.setAttribute('class','row selected');
}

function printPacketDetails(pkt_num) {
    var packet = getDissectedPacket(pkt_num);
    if (!packet) return;

    
    pktdetails.innerHTML = '';
    
    while (packet !== null) { // print details for each header
        pktdetails.appendChild(packet.printDetails(pkt_num));
        packet = packet.next_header;        
    }
}

function printPayload(pkt_num) {   
    var payload = getRawPacket(pkt_num);
    if (!payload) return;
    
    payload = new Uint8Array(payload);
                
    var output = '';
        
    var remainder = payload.byteLength % 16;
    
    var i, j;
    
    for (i = 0; i < payload.byteLength - 16; i += 16) {
        output += printNum(i, 16, 4)+'  ';
        for (j = 0; j < 16; j++) {
            output += printNum(payload[i + j], 16, 2) + ' ';
            if (j === 7)
                output += ' ';
        }
        output += ' ';
        for (j = 0; j < 16; j++) {
            if (payload[i + j] >= 32 && payload[i + j] <= 126)
                output += String.fromCharCode(payload[i + j]);
            else
                output += '.';
        }
        output += '\n';
    }
    
    output += printNum(i, 16, 4)+'  ';
    for (j = 0; j < remainder; j++) {
        output += printNum(payload[i + j], 16, 2) + ' ';
        if (j === 7)
            output += ' ';
    }
    
    for (j = 0; j < (16 - remainder); j++) {
        output += '   ';
        if (j === 7)
            output += ' ';
    }
    output += ' ';
    
    for (j = 0; j < remainder; j++) {
        if (payload[i + j] >= 32 && payload[i + j] <= 126)
            output += String.fromCharCode(payload[i + j]);
        else
            output += '.';
    }
    
    //pktpayload.innerHTML = output;
    pktpayload.innerHTML = '';
    pktpayload.appendChild(doc.createTextNode(output));
}



function switchConnection() {
    if(ws) {
        ws.close();
        ws = null;
        return;
    }
    ws = new WebSocket(ws_url);
    ws.binaryType = 'arraybuffer';
    ws.onopen = onWSOpen;
    ws.onclose = onWSClose;
    ws.onmessage = onWSMessage;        
}


















function processMouseWheel() {
    scroll(event.wheelDelta / -24);
    return false;
}

var scrollInterval;

function startScrolling(direction) {
    clearTimeout(scrollInterval);
    scrollInterval = setInterval(function() {scroll(direction);}, 20);
}

function stopScrolling() {
    clearTimeout(scrollInterval);
}

function scroll(direction) {
    if (packetView)
        scrollPacketView(direction);
    else
        scrollConnectionView(direction);
}

function scrollPacketView(direction) {
    if (pkts.length === 0)
        return;
    
    autoscroll = false;
    renderNextTime = true;
    
    scrollanchor += direction;
    
    if (scrollanchor < 0)
        scrollanchor = 0
    else if (scrollanchor >= pkts.length - maxPackets) {
        // we don't want a negative anchor
        scrollanchor = Math.max(pkts.length - maxPackets, 0);
        autoscroll = true;
    }
}

function connectionViewSeek(direction) {
    var tuple = connectionViewLength();
    var length = tuple[0];
    var anchor = tuple[1];   
    
    if (direction > 0 && direction >= length - anchor - maxPackets) {
        autoscroll = true;
        direction = length - anchor - maxPackets;
    }
    if (direction === 0)
        return;
    
    var currentConnection;
    
    while (direction !== 0) {
        pktAnchor += direction;
        
        currentConnection = conns[connAnchor];
        
        if (pktAnchor < -1) {
            direction = (pktAnchor + 2);
            connAnchor--;
            
            if (connAnchor < 0) {
                connAnchor = 0;
                pktAnchor = -1;
                break;
            }
            
            currentConnection = conns[connAnchor];
            pktAnchor = (currentConnection.packets.length * currentConnection.visible) - 1;
        }
        else if (pktAnchor >= currentConnection.packets.length * currentConnection.visible) {
            direction = (pktAnchor - currentConnection.packets.length * currentConnection.visible);
            connAnchor++;
            
            if (connAnchor >= conns.length) {
                alert('BUG!')
                connAnchor = conns.length - 1;
                currentConnection = conns[connAnchor];
                pktAnchor = (currentConnection.packets.length * currentConnection.visible) - 1;
                direction = 0;
            }            
            pktAnchor = -1;
        }
        else
            direction = 0;
    }
}

function scrollConnectionView(direction) {
    if (conns.length === 0)
        return;
    
    autoscroll = false;
    renderNextTime = true;
    
    connectionViewSeek(direction);
    
    
}

function updateConnectionView() {        
    var i = connAnchor;
    var j = pktAnchor;
    
    var rows = pkttable.getElementsByClassName('row');
    
    for (var k = rows.length - 1; k >= 0; k--) {
        if (j === -1) {
            updateConnectionHeader(i, rows[k]); 
            if (--i < 0)
                return;            
            j = conns[i].packets.length * conns[i].visible - 1;
        }
        else // don't update pkts, they don't change...
            j--;
    }
}

function renderConnectionView() {
    if (conns.length === 0)
        return;
    if (!renderNextTime) {
        // updateConnectionView();
        return;
    }
    
    var c = connAnchor;
    var p = pktAnchor;
   
    pkttable.innerHTML = '';
    
    var row;
    
    for (var i = 0; i <= maxPackets; i++) {
        if (p === -1)
            row = printConnectionHeader(c);
        else
            row = printRow(conns[c].packets[p], 'gray');
        pkttable.appendChild(row);
        
        p++;
        
        if (p >= conns[c].packets.length * conns[c].visible) {
            p = -1;
            c++;
            if (c >= conns.length)
                break;
        }
    }
    
    if (autoscroll)
        pktoutput.scrollTop = pktoutput.scrollHeight;
    else
        pktoutput.scrollTop = 0;
    
    renderNextTime = false;
    
//     if (pktAnchor > -1)
//         row = printRow(currentConnection.packets[pktAnchor], 'gray');
//     else
//         row = printConnectionHeader(connAnchor);
//     
//     pkttable.appendChild(row);
//     shownPackets = 1;
//     
//     var i = connAnchor;
//     var j = pktAnchor - 1;
//     
//     if (j < -1 && --i >= 0) {        
//         currentConnection = conns[i];
//         j = (currentConnection.packets.length * currentConnection.visible) - 1;
//     }
//     
//     while (i >= 0) {
//         if (pktoutput.scrollHeight > pktoutput.clientHeight)
//             break;
//         
//         currentConnection = conns[i];
//         
//         if (j > -1)
//             row = printRow(currentConnection.packets[j], 'gray');
//         else
//             row = printConnectionHeader(i);
// 
//         pkttable.insertBefore(row, pkttable.firstChild);
//         shownPackets++;
//         
//         j--;
//         
//         if (j < -1) {
//             if (--i < 0)
//                 break;
//             
//             currentConnection = conns[i];
//             j = (currentConnection.packets.length * currentConnection.visible) - 1;
//         }
//     }
//     
//     i = connAnchor;
//     j = pktAnchor + 1;
//     currentConnection = conns[i];
//     
//     if (j >= currentConnection.packets.length * currentConnection.visible && ++i < conns.length) {
//         currentConnection = conns[i];
//         j = -1;
//     }
//     
//     while (i < conns.length) {
//         if (pktoutput.scrollHeight > pktoutput.clientHeight)
//             break;
//         
//         currentConnection = conns[i];
//         
//         if (j > -1)
//             row = printRow(currentConnection.packets[j], 'gray');
//         else
//             row = printConnectionHeader(i);
// 
//         pkttable.appendChild(row);
//         shownPackets++;
//         // FIXME
//         // we always want the anchor to be the last element..
//         connAnchor = i;
//         pktAnchor = j;
//         
//         j++;
//                 
//         if (j >= currentConnection.packets.length * currentConnection.visible) {
//             if (++i >= conns.length)
//                 break;
//             
//             currentConnection = conns[i];
//             j = -1;
//         }
//     }
//     
//     if (autoscroll)
//         pktoutput.scrollTop = pktoutput.scrollHeight;
}

function printConnectionHeader(connectionNumber) {
    var connection = conns[connectionNumber];
    
    if (!connection) {
        return;
        alert(connectionNumber)
    }
    
    row = doc.createElement('div');    

    row.setAttribute('onclick','processClick(this, "' + connection.id + '")');
    row.setAttribute('oncontextmenu','processRightClick(this, "' + connection.id + '", event, "' + connection.id + '")');
    row.setAttribute('class','row ' + connection.packets[0].prot);
    
    var drop = doc.createElement('div');
    var num  = doc.createElement('div');
    var src  = doc.createElement('div');
    var dst  = doc.createElement('div');
    var prot = doc.createElement('div');
    var len  = doc.createElement('div');
    var info = doc.createElement('div');
       
    drop.setAttribute('class', 'col 2p');
    num.setAttribute('class', 'col 8p tr');    
    src.setAttribute('class', 'col 20p'); 
    dst.setAttribute('class', 'col 20p'); 
    prot.setAttribute('class', 'col 10p');    
    len.setAttribute('class', 'col 10p tr');    
    info.setAttribute('class', 'col 30p');
    
    var icon = doc.createElement('span');
    if (connection.visible)
        icon.setAttribute('class', 'dropdown glow clicked');
    else
        icon.setAttribute('class', 'dropdown glow');
    icon.setAttribute('onclick', 'switchVisibility(this,' + connectionNumber + ')');
    drop.appendChild(icon);    
    
    num.innerHTML  = connection.num;
    src.innerHTML  = connection.src + ':' + connection.sport;
    dst.innerHTML  = connection.dst + ':' + connection.dport;
    prot.innerHTML = connection.packets[0].prot;
    len.innerHTML  = printSize(connection.len);
    if (filter === connection.id)
        info.innerHTML = 'Following';
    
    row.appendChild(drop);
    row.appendChild(num);
    row.appendChild(src);
    row.appendChild(dst);
    row.appendChild(prot);
    row.appendChild(len);
    row.appendChild(info);
    
    return row;
}

function updateConnectionHeader(connectionNumber, row) {
    var connection = conns[connectionNumber];
    
    if (!connection || !row) 
        return;
    
    var cols = row.getElementsByTagName('div');
    
    cols[1].innerHTML  = connection.num;
    cols[2].innerHTML  = connection.src + ':' + connection.sport;
    cols[3].innerHTML  = connection.dst + ':' + connection.dport;
    cols[4].innerHTML = connection.packets[0].prot;
    cols[5].innerHTML  = printSize(connection.len);
}

function switchVisibility(dropdown, connectionNumber) {
    var connection = conns[connectionNumber];
    
    if (!connection) 
        return;
    
    autoscroll = false;
    
    if (connection.visible) {
        connection.visible = 0;
        dropdown.className = 'dropdown glow';
    }
    else {
        connection.visible = 1;
        dropdown.className = 'dropdown glow clicked';
    }
    
    renderNextTime = true; // show the changes
}

function followStream(id) {  
    if (filter === id) {
        filter = false;
        pkts = getDissectedPackets();
    }
    else {
        packetView = true;
        filter = id;
        pkts = getConnectionById(id).packets;
    }
    // we don't want a negative anchor
    scrollanchor = Math.max(0, pkts.length - maxPackets);
    autoscroll = true;
    renderNextTime = true;
}






























/*
 * deprecated methods... these might be used for performance tests
 * 
 * later they'll be send to programmer's hell :-P
 */
// var connview = doc.getElementById('connview');
// var connoutput = connview.getElementsByClassName('output')[0];
// var conntable = connoutput.getElementsByTagName('div')[0];
// var conndetails = connview.getElementsByClassName('details')[0];
// var connpayload = connview.getElementsByClassName('details')[1];
// 
// function switchView_old() {
//     packetView = !packetView;
//     if (packetView) {
//         connview.setAttribute('class', 'hidden');
//         pktview.removeAttribute('class');
//     }
//     else {
//         pktview.setAttribute('class', 'hidden');
//         connview.removeAttribute('class');
//     }
// }
// 
// function switchVisibility_old(dropdown, id) {
//     var container = doc.getElementById(id);
//     if (container.className === 'hidden') {
//         container.className = 'table gray borderbottom';
//         dropdown.className = 'dropdown clicked';
//     }
//     else {
//         container.className = 'hidden';
//         dropdown.className = 'dropdown';
//     }
// }
// 
// function print(packet) {
//     if (pktoutput.scrollHeight > pktoutput.clientHeight) {
//         pkttable.removeChild(pkttable.firstChild);
//     }
//     
//     printConnection(packet);
//     
//     var row = printRow(packet);
//     if (tcp_filter && packet.tcp_id !== tcp_filter)
//         return;
//     pkttable.appendChild(row);
// }
// 
// function printConnection(packet) {
//     if (!packet.tcp_id) 
//         return;
//     
//     var conn = getTCPConn(packet.tcp_id);
//     
//     var row = connRows[packet.tcp_id];
//     
//     if (!row) {
//         row = connRows[packet.tcp_id] = new Object();
//         row.root = doc.createElement('div');
//         row.row = doc.createElement('div');
//                 
//         row.root.setAttribute('class', 'hidden');
//         row.root.setAttribute('id', packet.tcp_id);
//         
//         row.row.setAttribute('onclick','processClick(this, "' + packet.tcp_id + '")');
//         row.row.setAttribute('class','row ' + packet.prot);
//         
//         conntable.appendChild(row.row);
//         conntable.appendChild(row.root);
//     }
//         
//     var num   = doc.createElement('div');
//     var src  = doc.createElement('div');
//     var dst  = doc.createElement('div');
//     var prot = doc.createElement('div');
//     var len  = doc.createElement('div');
//     var info = doc.createElement('div');
//     
//     
//     
//     row.root.appendChild(printRow(packet));
//         
//     num.setAttribute('class', 'col 5p tr');    
//     src.setAttribute('class', 'col 25p'); 
//     dst.setAttribute('class', 'col 25p'); 
//     prot.setAttribute('class', 'col 10p');    
//     len.setAttribute('class', 'col 5p');    
//     info.setAttribute('class', 'col 30p');
//     
//     var dropdown = doc.createElement('span');
//     
//     dropdown.setAttribute('class', 'dropdown');
//     dropdown.setAttribute('onclick', 'switchVisibility(this,' +
//                                      '"' + packet.tcp_id + '")');
//     
//     num.appendChild(dropdown);
//     num.innerHTML  += conn.num;
//     src.innerHTML   = conn.src + ':' + conn.sport;
//     dst.innerHTML   = conn.dst + ':' + conn.dport;
//     prot.innerHTML  = packet.prot;
//     len.innerHTML   = printSize(conn.len);
//     
//     row.row.innerHTML = '';
//     row.row.appendChild(num);
//     row.row.appendChild(src);
//     row.row.appendChild(dst);
//     row.row.appendChild(prot);
//     row.row.appendChild(len);
//     row.row.appendChild(info);
//     
//     return row.row;
// }
// 
// function printConnections() {
//     var tcpConns = getTCPConns();
//     
//     for (id in tcpConns) 
//         printConnection(tcpConns[id].pkts[0]);
// }
// 
// function filterTCPConn_old(tcp_id) {   
//     var f;
//     if (tcp_filter === tcp_id) {
//         tcp_filter = false;
//         f = function() {printPackets(getPackets());}
//     }
//     else {
//         tcp_filter = tcp_id;
//         f = function() {printPackets(getTCPConn(tcp_id).pkts);}
//     }
//     clearScreen(f);
// }
// 
// function printPackets(pkts) {
//     if (!pkts) return;
//     
//     var i = 0;
//     var stepSize = Math.min(Math.ceil(pkts.length / 10), 5000);
//     
//     anim = requestAnimationFrame(drawStep);
//     
//     function drawStep() {        
//         var upperLimit = i + stepSize;
//         
//         for (; i < pkts.length && i < upperLimit; i++) {
//             if (pkts[i].num === selectedPacketRow.num) {
//                 var row = printRow(pkts[i]);
//                 pkttable.appendChild(row);
//                 selectRow(row, pkts[i].num);
//                 printPacketDetails(pkts[i].num);
//                 printPayload(pkts[i].num);
//             }
//             else
//                 pkttable.appendChild(printRow(pkts[i]));            
//         }
//         
//         var percent = (i * 100 / pkts.length) | 0;
//         progressBarPercent.innerHTML = percent;
//         progressBarBox.style.width = percent + '%';
//         
//         if (i >= pkts.length) {   
//             progressBar.className = 'hidden';
//             cancelAnimationFrame(anim);            
//         }
//         else     
//             anim = requestAnimationFrame(drawStep);
//     }
//     
// //     for (var i = 0; i < pkts.length; i++) {
// //         if (pkts[i].num === selectedPacketRow.num) {
// //             var row = printRow(pkts[i]);
// //             pkttable.appendChild(row);
// //             selectRow(row, pkts[i].num);
// //             printPacketDetails(pkts[i].num);
// //             printPayload(pkts[i].num);
// //         }
// //         else
// //             pkttable.appendChild(printRow(pkts[i]));
// //         
// //         draw--;
// //         if (draw <= 0) {
// //             draw = 30;
// //         }
// //     }
// }

// // FIXME FIXME FIXME
// function clearScreen(f) {
//     return;
//     var rownum = pkttable.getElementsByClassName('row').length;
//     var stepSize = Math.min(Math.ceil(rownum / 20), 5000);
//     
//     anim = requestAnimationFrame(
//         function() {
//             progressBar.className = '';
//             removeRow();        
//         });
//     
//     pktdetails.innerHTML = '';
//     pktpayload.innerHTML = '';
//     
//     var count = 0;
//     
//     function removeRow() {
//         for (var i = 0; i < stepSize; i++) {
//             if (!pkttable.firstChild)
//                 break;
//             pkttable.removeChild(pkttable.firstChild);
//             count++;
//         }
//         
//         var percent = (count * 100 / rownum) | 0;
//         progressBarPercent.innerHTML = percent;
//         progressBarBox.style.width = percent + '%';
//         
//         if (!pkttable.firstChild) {
//             if (f) {         
//                 anim = requestAnimationFrame(f);                
//             }
//             else {
//                 progressBar.className = 'hidden';
//                 cancelAnimationFrame(anim);
//             }
//         }  
//         else
//             anim = requestAnimationFrame(removeRow);
//     }
// }

// var progressBar        = doc.getElementById('progressbar');
// var progressBarBox     = progressBar.getElementsByTagName('div')[0];
// var progressBarPercent = progressBar.getElementsByTagName('span')[0];