window.requestAnimationFrame = window.requestAnimationFrame || 
                               window.mozRequestAnimationFrame || 
                               window.oRequestAnimationFrame ||
                               window.webkitRequestAnimationFrame;
                               
if (!window.requestAnimationFrame) {
    window.requestAnimationFrame = 
    function (callback) {
        return setTimeout(callback, 2);
    }
    alert('Hi there!\n\
           Your browser does not support the nifty method \
           requestAnimationFrame, so I will render your session \
           via setTimeout.');
}
                               
window.cancelAnimationFrame =  window.cancelAnimationFrame ||
                               window.cancelTimeout;

var doc = document;
var pktoutput = doc.getElementById('output');
var pkttable  = pktoutput.getElementsByTagName('div')[0];
var pktdetails = doc.getElementById('details');
var pktpayload = doc.getElementById('raw');

var selectedPacketRow = new Object();
var selectedConnectionRow = new Object();

var ws_url = 'ws://' + window.location.host + '/binary';
var ws = null;  
var conn_button = doc.getElementById('startcap');

var MINSCROLLBARSIZE = 28;
var MAXSCROLLBARSTART;
var currentRow = 0;
var rows = [];

var packetView = false; // makes connection view the default
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

var serverFilter = 'none'; // default filter

var JSEVENTS = 
[
    ['body', 'onclick', 'closeContextMenu()'],
    ['body', 'onmouseup', 'deselectScrollbox()'],
    ['body', 'onmousemove', 'moveScrollbox(event)'],
    ['body', 'onresize', 'processResize()'],
    ['startcap', 'onclick', 'switchConnection()'],
    ['clearscr', 'onclick', 'clearScreen()'],
    ['savecap', 'onclick', 'saveCapture()'],
    ['loadcap', 'onclick', 'clickOnFileInput()'],
    ['fileInput', 'onchange', 'readPcapFile(this.files[0])'],
    ['switchview', 'onclick', 'switchView()'],
    ['filterForm', 'onsubmit', 'return processFilter()'],
    ['output', 'oncontextmenu', 'return false'],
    ['output', 'onmousewheel', 'processMouseWheel(event)'],
    ['table', 'oncontextmenu', 'return false'],    
    ['scrollup', 'onmousedown', 'startScrolling(-1)'],
    ['scrollup', 'onmouseup', 'stopScrolling()'],
    ['scrollbar', 'onmousedown', 'selectScrollbox()'],
    ['scrolldown', 'onmousedown', 'startScrolling(1)'],
    ['scrolldown', 'onmouseup', 'stopScrolling()']
];

function initJSEvents() {
    for (var i = 0; i < JSEVENTS.length; i++)
        doc.getElementById(JSEVENTS[i][0])
           .setAttribute(JSEVENTS[i][1], JSEVENTS[i][2]);
}

function onFirstMessage(msg) {
    switch(String.fromCharCode(new Uint8Array(msg.data, 0, 1)[0])) {
    case 'O':  
        if (serverFilter !== 'none')
            filterField.style.backgroundColor = '#afffaf';
        ws.onmessage = onWSMessage;
        dissectMessage(msg.data.slice(1));
        return;
    case 'E':
    default:
        filterField.style.backgroundColor = '#ffafaf';
        switchConnection();
        return;
    }
}

function onWSMessage(msg) {
    dissectMessage(msg.data);
}

function dissectMessage(data) {
    var oldLength, oldAnchor, length, anchor;
    
    if (packetView) oldLength = pkts.length;
    else {
        var tuple = connectionViewLength();
        oldLength = tuple[0];
        oldAnchor = tuple[1];
    }
    
    dissect(data);
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
    else if (!packetView) {
        // FIXME: what happens if connection is extended BELOW anchor...
        if (oldAnchor === anchor && oldLength - oldAnchor >= maxPackets)
            return;
        renderNextTime = true;
    }
}  

function onWSOpen() {
    ws.send(serverFilter);
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

initJSEvents();
processResize();
switchConnection();

function processResize() {
    doc.body.style.fontSize = '0.9vw';
    
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

function processFilter() {
    serverFilter = filterField.value;
    return false;
}

function switchView() {
    packetView = !packetView;
    renderNextTime = true;
}

function saveCapture() {
    downloadFileFromURI(getURL(), 'log.pcap');
} 

function downloadFileFromURI(uri, filename) {
    if (!uri)
        return;
    
    var tmpLink = document.createElement('a'); // link to be 'clicked' on
    var mc = document.createEvent('MouseEvents'); // event to 'click' on it
    
    mc.initEvent('click', true, false);
    
    if (filename)
        tmpLink.download = filename;    
    tmpLink.href = uri;
    
    tmpLink.dispatchEvent(mc); //'click' on the link
}

function clickOnFileInput() {
    fileInput.dispatchEvent(mc);
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
    len.setAttribute('class', 'col 10p tr mono');    
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
    pktoutput.unselectable = 'on';
    pktdetails.unselectable = 'on';
    pktpayload.unselectable = 'on';
    return false;
}

function deselectScrollbox() {
    scrollbarSelected = false;
    doc.body.className = ''; // re-enable (text) selection
    pktoutput.unselectable = 'off';
    pktdetails.unselectable = 'off';
    pktpayload.unselectable = 'off';
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

        connAnchor = 0;
        pktAnchor = -1;        
        scrollConnectionView(newPos);
    }        
  
}

// FIXME
// setInterval(render, 200);
var renderThread;
startRendering();

function stopRendering() {
    window.cancelAnimationFrame(renderThread);
}

function startRendering() {
    renderThread = window.requestAnimationFrame(render);
}

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
    
    var follow = doc.createElement('span');
    follow.setAttribute('onclick','followStream("' + id + '")');
    follow.setAttribute('class', 'contextentry');
    
    var srcContent = doc.createElement('span');
    srcContent.setAttribute('onclick','downloadContent("' + id + '", 1)');
    srcContent.setAttribute('class', 'contextentry');
    srcContent.innerHTML = 'Save source content';

    var dstContent = doc.createElement('span');
    dstContent.setAttribute('onclick','downloadContent("' + id + '", 0)');
    dstContent.setAttribute('class', 'contextentry');
    dstContent.innerHTML = 'Save destination content';
    
    if (filter === id)
        follow.innerHTML = 'Unfollow';
    else
        follow.innerHTML = 'Follow this stream';
    
    contextMenu.appendChild(follow);
    contextMenu.appendChild(doc.createElement('br'));
    contextMenu.appendChild(srcContent);
    contextMenu.appendChild(doc.createElement('br'));
    contextMenu.appendChild(dstContent);
    
    if (!connectionsById[id] || !connectionsById[id].contents)
        return false;
    
    return false;
}

function downloadContent(id, src) {
    var contents = src ? connectionsById[id].srcC.content : connectionsById[id].dstC.content;
    if (contents.length === 0)
        return;
    
    var data = [];
    
    for (var i = 0; i < contents.length; i++)
        data[i] = contents[i][0].slice(contents[i][1]);
    
    data = mergeBuffers(data);
    
    downloadFileFromURI(createURI('application/x-download', data), id);
}

function render() {    
    if (packetView)
        renderPacketView();
    else {
        renderConnectionView();        
    }
    calculateScrollbarSize();
    
    window.requestAnimationFrame(render);
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
    ws.onmessage = onFirstMessage;        
}











function processMouseWheel(event) {
    event = window.event || event;
    var wheelDelta = event.detail ? event.detail * 5 : event.wheelDelta / -24;
    scroll(wheelDelta);
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
    
    for (var k = 0; k < rows.length; k++) {
        if (j === -1) updateConnectionHeader(i, rows[k]);
        if (++j >= conns[i].packets.length * conns[i].visible) {
            i++;
            j = -1;
        }
    }
}

function renderConnectionView() {
    if (conns.length === 0)
        return;
    if (!renderNextTime) {
        updateConnectionView();
        return;
    }
    
    var c = connAnchor;
    var p = pktAnchor;
   
    pkttable.innerHTML = '';
    
    var row, num;
    
    for (var i = 0; i <= maxPackets; i++) {
        if (p === -1) {
            row = printConnectionHeader(c);
            num = conns[c].id;            
        }
        else {
            row = printRow(conns[c].packets[p], 'gray');
            num = conns[c].packets[p].num;
        }
        pkttable.appendChild(row);
        if (num === selectedConnectionRow.num)
            selectRow(row, num);
        
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
    row.className = 'row ' + (connection.class || connection.prot);
    
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
    len.setAttribute('class', 'col 10p tr mono');    
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
    prot.innerHTML = connection.prot;
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
    
    if (selectedConnectionRow.num !== connection.id)
        row.className = 'row ' + (connection.class || connection.prot);
    
    var cols = row.getElementsByTagName('div');
    
    cols[1].innerHTML  = connection.num;
    cols[2].innerHTML  = connection.src + ':' + connection.sport;
    cols[3].innerHTML  = connection.dst + ':' + connection.dport;
    cols[4].innerHTML  = connection.prot;
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