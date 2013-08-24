'use strict';

var selectedPacketRow = {};
var selectedConnectionRow = {};

var webSocketURL = 'ws://' + window.location.host + '/binary';
var webSocket = null;  

var startCapture = document.getElementById('startcap');

var serverFilter;

var cache = null;

var dissector = null;

var mainOutput = document.getElementById('output');
var mainOutputTable  = document.getElementById('table');
var detailsOutput = document.getElementById('details');
var bytesOutput = document.getElementById('raw');

var packetView = false; // connection view as default
var contextMenu = document.getElementById('contextmenu');

var renderThread;
var renderNextTime = false;

var autoscroll = true;

var maxRows = 0;

var doubleBuffer = document.createDocumentFragment();

var followID = false;

initWebPcapJS();

function initWebPcapJS () {
    initFileIO();
    initGUI();
    processResize();
    dissector = new Dissector();
    initJSEvents();    
    startRendering();
    switchConnection();
    packets = dissector.getDissectedPackets();
    conns = dissector.getConnectionsByArrival();
}

function initJSEvents() {
    window.addEventListener('resize', processResize);
    document.addEventListener('click', closeContextMenu);
    document.addEventListener('mouseup', processMouseUp);
    document.addEventListener('mousemove', processMouseMove);    
    document.getElementById('startcap').addEventListener('click', switchConnection);
    document.getElementById('clearcap').addEventListener('click', dissector.init());
    document.getElementById('savecap').addEventListener('click', saveCapture);
    document.getElementById('loadcap').addEventListener('click', function () {simulateClickOn(document.getElementById('fileinput'));});
    document.getElementById('fileinput').addEventListener('change', function () {readPcapFile(this.files[0], dissector);});
    document.getElementById('switchview').addEventListener('click', switchView);
    document.getElementById('filterform').addEventListener('submit', processFilter);
    document.getElementById('output').addEventListener('contextmenu', function (event) {event.preventDefault();}, false);
    document.getElementById('output').addEventListener('mousewheel', processMouseWheel);
    document.getElementById('output').addEventListener('wheel', processMouseWheel);
    document.getElementById('table').addEventListener('contextmenu', function (event) {event.preventDefault();}, false);
    document.getElementById('scrollbar-track').addEventListener('mousedown', function () {startTrackScrolling(true);});
    document.getElementById('scroll-thumb').addEventListener('mousedown', selectScrollThumb);
    document.getElementById('scrollbar-button-up').addEventListener('mousedown', function () {startScrolling(-1)});
    document.getElementById('scrollbar-button-down').addEventListener('mousedown', function () {startScrolling(1)});
    document.getElementById('contextmenu').addEventListener('selectstart', function (event) {event.preventDefault();}, false);
}

function onFirstMessage(msg) {
    switch (String.fromCharCode(new Uint8Array(msg.data, 0, 1)[0])) {
    case 'O':  
        if (serverFilter)
            filterField.style.backgroundColor = '#afffaf';
        webSocket.onmessage = onSecondMessage;
        onSecondMessage({data: msg.data.slice(1)});
        return;
    case 'E':
    default:
        if (serverFilter)
            filterField.style.backgroundColor = '#ffafaf';
        switchConnection();
        return;
    }
}

function onSecondMessage(msg) {    
    cache = mergeBuffers([cache, msg.data]);
    if (cache.byteLength < 24)
        return;
    
    readPcapGlobalHeader(cache, dissector);
    webSocket.onmessage = onWebSocketMessage;
    dissectMessage(cache.slice(24));
}

function onWebSocketMessage(msg) {
    dissectMessage(msg.data);
}

function dissectMessage(data) {
    var oldLength, oldAnchor, length, anchor;
    
    if (packetView) oldLength = packets.length;
    else {
        var tuple = connectionViewLength();
        oldLength = tuple[0];
        oldAnchor = tuple[1];
    }
    
    dissector.dissect(data);
    
    if (packetView)
        length = packets.length;
    else {
        var tuple = connectionViewLength();
        length = tuple[0];
        anchor = tuple[1];
    }
    
    if (oldLength === length)
        return;
    if (autoscroll) {
        if (packetView) {
            // we don't want a negative anchor     
            packetViewAnchor = Math.max(0, packets.length - maxRows);
            renderNextTime = true;
        }
        else {
            connectionViewSeek(Math.max(0, length - anchor - maxRows));
            renderNextTime = true;
        }
    }
    else if (!packetView) {
        // FIXME: what happens if connection is extended BELOW anchor...
        if (oldAnchor === anchor && oldLength - oldAnchor >= maxRows)
            return;
        renderNextTime = true;
    }
}  

function onWebSocketOpen() {
    webSocket.send(serverFilter || 'none\0');
    startCapture.setAttribute('title', 'Stop the running live capture');
    startCapture.innerHTML = '<img class="glow buttonicon" src="img/media-' + 
                             'playback-stop.svgz" alt="Stop capture">';
}
    
function onWebSocketClose() {
    webSocket = null;
    startCapture.setAttribute('title', 'Start a new live capture');
    startCapture.innerHTML = '<img class="glow buttonicon" src="img/media-' +
                             'record.svgz" alt="Start capture">';
    cache = null;
}

function processResize() {
    document.body.style.fontSize = '0.9vw';
    
    mainOutput.style.width = '100%';
    tableheader.style.width = '100%';
    
    tableheader.style.width = (tableheader.offsetWidth - 15) + 'px';
    mainOutput.style.width = (mainOutput.offsetWidth - 15) + 'px';
    
    scrollbar.style.height = mainOutput.offsetHeight + 'px';
    scrollbar.style.top =  mainOutput.offsetTop + 'px';
    scrollbar.style.left = mainOutput.offsetLeft + mainOutput.offsetWidth + 'px';
        
    scrollbarTrack.style.height = '100%';
    
    scrollbarTrack.style.height = (scrollbarTrack.offsetHeight - 30) + 'px';
    
    MAX_SCROLLTHUMB_OFFSET = scrollbarTrack.offsetHeight - MIN_SCROLLTHUMB_SIZE;
    
    maxRows = 0;
    mainOutputTable.innerHTML = '';
    
    while (mainOutput.scrollHeight <= mainOutput.clientHeight) {
        var row = document.createElement('div');
        var col = document.createElement('div');
        row.setAttribute('class','row');        
        col.setAttribute('class', 'col 5p');
        col.innerHTML = 'test';
        row.appendChild(col);
        mainOutputTable.appendChild(row);
        maxRows++;
    }
    
    mainOutputTable.innerHTML = '';
    renderNextTime = true;    
}

function processFilter() {
    serverFilter = filterField.value + '\0';
    return false;
}

function simulateClickOn(node) {
    var mouseClick; // event to 'click' with
    
    mouseClick = new MouseEvent('click'); 
    
    node.dispatchEvent(mouseClick);    
}

function downloadFileFromURI(resource, filename) {
    if (!resource)
        throw 'No resource specified to download from.';
    
    var tmpLink = document.createElement('a'); // link to be 'clicked' on
    
    if (filename)
        tmpLink.download = filename;    
    tmpLink.href = resource;
    
    simulateClickOn(tmpLink); //'click' on the link
}

function switchConnection() {
    if(webSocket) {
        webSocket.close();
        webSocket = null;
        return;
    }
    webSocket = new WebSocket(webSocketURL);
    webSocket.binaryType = 'arraybuffer';
    webSocket.onopen = onWebSocketOpen;
    webSocket.onclose = onWebSocketClose;
    webSocket.onerror = onWebSocketClose;
    webSocket.onmessage = onFirstMessage;        
}

function followStream(id) {  
    if (followID === id) {
        followID = false;
        packets = dissector.getDissectedPackets();
    }
    else {
        packetView = true;
        followID = id;
        packets = dissector.getConnectionById(id).packets;
    }
    // we don't want a negative anchor
    packetViewAnchor = Math.max(0, packets.length - maxRows);
    autoscroll = true;
    renderNextTime = true;
}

function initGUI() {
    // some cross-browser related stuff
    window.requestAnimationFrame = window.requestAnimationFrame || 
                                   window.mozRequestAnimationFrame || 
                                   window.oRequestAnimationFrame ||
                                   window.webkitRequestAnimationFrame;
                                   
    window.cancelAnimationFrame =  window.cancelAnimationFrame ||
                                   window.cancelTimeout;

    if (!window.requestAnimationFrame) {
        // create a pseudo-requestAnimationFrame method
        window.requestAnimationFrame = 
            function (callback) {
                return setTimeout(callback, 40); // roundabout 25 FPS
            }
            
        alert('Hi there!\n' +
            'Your browser does not support the nifty method ' +
            'requestAnimationFrame, so I will render your session ' +
            'via setTimeout.');
    }
}

function stopRendering() {
    window.cancelAnimationFrame(renderThread);
}

function startRendering() {
    renderThread = window.requestAnimationFrame(render);
}

function closeContextMenu() {
    contextMenu.className = 'hidden';
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

function processClick(row, num) {
    console.log(event);
    selectRow(row, num);
    
    if (packetView) {
        printPacketDetails(num);
        printPayload(num);
        return;
    }
    
    if (dissector.getConnectionById(num)) {
        printConnectionDetails(num);
        bytesOutput.innerHTML = '';
        return;
    }
    
    printPacketDetails(num);
    printPayload(num);
}

function processRightClick(row, num, event, id) {
    processClick(row, num);
    
    // skip non-UDP, non-TCP packets
    if (!id || !dissector.getConnectionsById()[id])
        return false;
    
    var follow, showContent, downloadSrcContent, downloadDstContent;
    

    
    follow = document.createElement('div');
    follow.setAttribute('onclick','followStream("' + id + '")');
    follow.setAttribute('class', 'contextentry');
    
    if (followID === id)
        follow.innerHTML = 'Unfollow';
    else
        follow.innerHTML = 'Follow this stream';
    
    doubleBuffer.innerHTML = '';
    doubleBuffer.appendChild(follow);
    
    if (dissector.getConnectionsById()[id].contents) {
        showContent = document.createElement('div');
        
        showContent.setAttribute('onclick','showContent("' + id + '")');
        showContent.setAttribute('class', 'contextentry');
        showContent.innerHTML = 'Show content';
        
        doubleBuffer.appendChild(showContent);
        
        if (dissector.getConnectionsById()[id].contents[0].length) {
            downloadSrcContent = document.createElement('div');
            
            downloadSrcContent.setAttribute('onclick','downloadContent("' + id + '", 0)');
            downloadSrcContent.setAttribute('class', 'contextentry');
            downloadSrcContent.innerHTML = 'Download source content';
                    
            doubleBuffer.appendChild(downloadSrcContent);
        }
        
        if (dissector.getConnectionsById()[id].contents[1].length) {
            downloadDstContent = document.createElement('div');
            
            downloadDstContent.setAttribute('onclick','downloadContent("' + id + '", 1)');
            downloadDstContent.setAttribute('class', 'contextentry');
            downloadDstContent.innerHTML = 'Download destination content';
            
            doubleBuffer.appendChild(downloadDstContent);            
        }
    }

    contextMenu.className = '';
    contextMenu.innerHTML = '';
    contextMenu.style.left = event.pageX + 'px';
    contextMenu.style.top = event.pageY + 'px';
    contextMenu.appendChild(doubleBuffer);
    
    return false;
}

function downloadContent(id, srcOrDst) {
    var contents = dissector.getConnectionsById()[id].contents[srcOrDst];
    
    if (contents.length === 0)
        return;
    
    var data = [];
    
    for (var i = 0; i < contents.length; i++)
        data[i] = contents[i].data.slice(contents[i].offset);
        
    downloadFileFromURI(createURI('application/x-download', data), id);
}

function showContent(id) {
    var contents = dissector.getConnectionsById()[id].mergeContent();
    
    if (contents.length === 0)
        return;
    
    var data = [];
    var srcOrDst = contents[0].srcOrDst;
        
    var box = document.createElement('div');
    box.className = 'contentbox';
    
    for (var i = 0; i < contents.length; i++) {
        if (srcOrDst !== contents[i].srcOrDst) {
            data = new Uint8Array(mergeBuffers(data));
            
            var text = '';
            for (var j = 0; j < data.length; j++)
                text += printASCII(data[j]);

            var span = document.createElement('span');
            span.className = ((srcOrDst && 'src') || 'dst') + 'content';
            span.appendChild(document.createTextNode(text));
            
            box.appendChild(span);
            
            data = [];
            srcOrDst = contents[i].srcOrDst;
        }
        data.push(contents[i].data.slice(contents[i].offset));
    }
    data = new Uint8Array(mergeBuffers(data));
    
    var text = '';
    for (var j = 0; j < data.length; j++)
        text += printASCII(data[j]);

    var span = document.createElement('span');
    span.className = ((srcOrDst && 'src') || 'dst') + 'content';
    span.appendChild(document.createTextNode(text));
    
    box.appendChild(span);
    
    var w = window.open('tcpcontent.html', 'content', 'width=640, height=480, status=yes, resizable=yes');
    w.onload = function() {w.document.body.appendChild(box); w.connection = dissector.getConnectionsById()[id]};
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

function switchView() {
    packetView = !packetView;
    renderNextTime = true;
}

function saveCapture() {
    downloadFileFromURI(getPcapURI(dissector), 'log.pcap');
}