'use strict';

var selectedPacketRow = {};
var selectedConnectionRow = {};

var webSocketURL = 'ws://' + window.location.host + '/binary';
var webSocket = null;  

var startCapture = document.getElementById('startcap');

var cache = new ArrayBuffer(0);

var dissector = null;

var mainOutput = document.getElementById('output');
var mainOutputTable  = document.getElementById('table');
var detailsOutput = document.getElementById('details');
var bytesOutput = document.getElementById('raw');
var filterField = document.getElementById('filterfield');

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
    // these refs are used by packet and connection view
    packets = dissector.getDissectedPackets();
    conns = dissector.getConnectionsByArrival();
}

function initJSEvents() {
    window.addEventListener('resize', processResize);
    document.addEventListener('click', closeContextMenu);
    document.addEventListener('mouseup', processMouseUp);
    document.addEventListener('mousemove', processMouseMove);    
    document.getElementById('startcap').addEventListener(
        'click', openWebSocket);
    document.getElementById('clearcap').addEventListener('click',
        function () {
            dissector.reset();
            packets = dissector.getDissectedPackets();
            conns = dissector.getConnectionsByArrival();
            table.innerHTML = '';
            autoscroll = true;
            renderNextTime = true;
        });
    document.getElementById('savecap').addEventListener('click', saveCapture);
    document.getElementById('loadcap').addEventListener('click', 
        function () {
            simulateClickOn(document.getElementById('fileinput'));            
        });
    
    document.getElementById('fileinput').addEventListener('change', 
        function () {
            readPcapFile(this.files[0], dissector);
            this.files = [];            
        });
    
    document.getElementById('switchview').addEventListener('click', switchView);
    document.getElementById('filterfield').addEventListener('keydown', 
        function (event) {
            if (event.keyCode === 13) { // ENTER
                if (webSocket)
                    closeWebSocket();
                openWebSocket();
            }
        }, false);
    
    document.getElementById('output').addEventListener('contextmenu', 
        function (event) {
            event.preventDefault();            
        }, false);
    
    document.getElementById('output').addEventListener(
        'mousewheel', processMouseWheel);
    document.getElementById('output').addEventListener(
        'wheel', processMouseWheel);
    document.getElementById('table').addEventListener('contextmenu', 
        function (event) {
            event.preventDefault();            
        }, false);
    
    document.getElementById('scrollbar-track').addEventListener('mousedown', 
        function () {
            startTrackScrolling(true);
        });
    
    document.getElementById('scroll-thumb').addEventListener(
        'mousedown', selectScrollThumb);
    document.getElementById('scrollbar-button-up').addEventListener('mousedown', 
        function () {
            startScrolling(-1);            
        });
    
    document.getElementById('scrollbar-button-down').addEventListener(
        'mousedown', function () {
            startScrolling(1);            
        });
    document.getElementById('contextmenu').addEventListener('selectstart', 
        function (event) {
            event.preventDefault();            
        }, false);
}

function openWebSocket() {
    if (webSocket) {
        closeWebSocket();
        console.log('Warning: WebSocket appears to still have been open.');
    }
    webSocket = new WebSocket(webSocketURL);
    webSocket.binaryType = 'arraybuffer';
    webSocket.onopen = onWebSocketOpen;
    webSocket.onclose = onWebSocketClose;
    webSocket.onerror = onWebSocketClose;
    webSocket.onmessage = onFirstMessage;   
}

function closeWebSocket() {
    if (!webSocket) {
        console.log('Warning: WebSocket has already been closed.');
        return;
    }
    webSocket.close(); 
    webSocket = null;    
}

// there are three onMessage methods to avoid having an if(...) for each packet

// onFirstMessage: process filter response code
// onSecondMessage: read pcap global header
// onMessage: dissect packets

function onFirstMessage(msg) {
    var serverResponse;
    
    if (msg.data.byteLength <= 0) {// that's wrong.. but next pkt might be fine
        console.log('Warning: Empty message received.');
        return;
    }
    
    serverResponse = printASCII(new DataView(msg.data).getUint8(0));
    // see how the server responded
    switch (serverResponse) {
    case 'O':
        try {
            if (filterField.value)
                filterField.style.backgroundColor = '#afffaf';
            onSecondMessage({data: msg.data.slice(1)});
            webSocket.onmessage = onSecondMessage;
        }
        catch (exception) {
            throw exception;
        }
        return;
    case 'E':
        if (filterField.value)
            filterField.style.backgroundColor = '#ffafaf';
        closeWebSocket();
        return;
    default:
        closeWebSocket();
        throw 'Invalid server response.';
    }
}

function onSecondMessage(msg) {
    // unlikely, but we may need to wait until 24 bytes were received
    cache = mergeBuffers([cache, msg.data]);
    
    if (cache.byteLength < 24)
        return;
    
    try {
        readPcapGlobalHeader(cache, dissector);
        dissectMessage(cache.slice(24));
        webSocket.onmessage = onMessage;    
    }
    catch (exception) {
        throw exception;        
    }
}

function onMessage(msg) {
    dissectMessage(msg.data);
}

function dissectMessage(data) {
    var oldLength, oldAnchor;
    var newLength, newAnchor;
    
    // get current values for length and anchor
    if (packetView) {
        oldLength = packets.length;
    }
    else {
        var cV = connectionViewLength();
        oldLength = cV.length;
        oldAnchor = cV.length;
    }
    
    // do some dissecting... this may no complete packet, but also several
    dissector.dissect(data);
    
    // get new values for length and anchor
    if (packetView)
        newLength = packets.length;
    else {
        var cV = connectionViewLength();
        newLength = cV.length;
        newAnchor = cV.anchor;
    }
    
    // take old and new values and decide if a visual update is necessary
    if (oldLength === newLength) // no new packets, no update needed
        return;
    
    if (autoscroll) {
        if (packetView) {
            // we don't want a negative anchor     
            packetViewAnchor = Math.max(0, newLength - maxRows);
            renderNextTime = true;
        }
        else {
            seekConnectionView(Math.max(0, newLength - newAnchor - maxRows));
            renderNextTime = true;
        }
    }
    // no autoscroll + packetView --> no visual update
    else if (!packetView) {
        // FIXME: what happens if connection is extended BELOW anchor...
        if (oldAnchor === newAnchor && oldLength - oldAnchor >= maxRows) {
            return;            
        }
        renderNextTime = true;
    }
}  

function onWebSocketOpen() {
    webSocket.send((filterField.value ? filterField.value : 'none') + '\0');
    
    startCapture.setAttribute('title', 'Stop the running live capture');
    startCapture.removeEventListener('click', openWebSocket);
    startCapture.addEventListener('click', closeWebSocket);
    startCapture.innerHTML = '<img class="glow buttonicon" src="img/media-' + 
                             'playback-stop.svgz" alt="Stop capture">';
    
    startCapture.addEventListener
}

function onWebSocketClose() {    
    startCapture.setAttribute('title', 'Start a new live capture');
    startCapture.removeEventListener('click', closeWebSocket);
    startCapture.addEventListener('click', openWebSocket);
    startCapture.innerHTML = '<img class="glow buttonicon" src="img/media-' +
                             'record.svgz" alt="Start capture">';
    cache = null;
}

function processResize() {
    var tableHeader = document.getElementById('tableheader');
    var testRow, testCol;
    
    // NOTE make that something more like (offsetWidth - padding)
    // set output width to 100% - 0.2% padding - 15px for scrollbar
    tableHeader.style.width = (document.body.offsetWidth * 0.998 - 15) + 'px';
    mainOutput.style.width = tableHeader.offsetWidth + 'px';
    
    // set height and position of scrollbar
    scrollbar.style.height = mainOutput.offsetHeight + 'px';
    scrollbar.style.top = mainOutput.offsetTop + 'px';
    scrollbar.style.left = mainOutput.offsetLeft + mainOutput.offsetWidth + 'px';
        
    // the track needs 15px space above and below for the buttons
    scrollbarTrack.style.height = mainOutput.offsetHeight - 15 + 'px';
    
    MAX_SCROLLTHUMB_OFFSET = scrollbarTrack.offsetHeight - MIN_SCROLLTHUMB_SIZE;
    
    // calculate how many rows mainOutput can hold now
    // NOTE this is done by creating a test row and measuring its height; there
    // might be a more elegant way to do this
    stopRendering();
    
    testRow = document.createElement('div');
    testCol = document.createElement('div');
    testRow.className = 'row';
    testCol.className = 'col';
    
    testCol.innerHTML = 'Height test';
    
    testRow.appendChild(testCol);
    
    mainOutputTable.innerHTML = '';
    mainOutputTable.appendChild(testRow);
    
    maxRows = Math.ceil(mainOutput.offsetHeight/ testRow.offsetHeight);
    
    // cleanup
    mainOutputTable.innerHTML = '';    
    renderNextTime = true;
    startRendering();
}

function simulateClickOn(node) {
    var mouseClick; // event to 'click' with
    
    mouseClick = document.createEvent('MouseEvent');
    mouseClick.initMouseEvent(
        'click', false, false, null, 0, 0, 0, 0, 0, false, false, false, false, 
        1, null);    
    
    node.dispatchEvent(mouseClick);    
}

function downloadFileFromURI(resource, filename) {
    var tmpLink = document.createElement('a'); // link to be 'clicked' on
    
    if (filename)
        tmpLink.download = filename;    
    tmpLink.href = resource;
    
    simulateClickOn(tmpLink); //'click' on the link
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

    // create a pseudo-requestAnimationFrame method
    if (!window.requestAnimationFrame) {
        window.requestAnimationFrame = (
            function (callback) {
                return setTimeout(callback, 40); // roundabout 25 FPS
            });
            
        console.log('Warning: Using setTimeout for rendering.');
    }
}

function stopRendering() {
    window.cancelAnimationFrame(renderThread);
}

function startRendering() {
    renderThread = window.requestAnimationFrame(render);
}

function openContextMenu(id, xPos, yPos) {
    // skip non-UDP, non-TCP packets
    if (!id || !dissector.getConnectionsById()[id])
        return;
    
    // the rows of the context menu    
    var followStream;
    var showContent;
    var downloadSrcContent, downloadDstContent;
    
    followStream = document.createElement('div');
    followStream.setAttribute('onclick','followStream("' + id + '")');
    followStream.setAttribute('class', 'contextentry');
    
    if (followID === id)
        followStream.innerHTML = 'Unfollow';
    else
        followStream.innerHTML = 'Follow this stream';
    
    doubleBuffer.innerHTML = '';
    doubleBuffer.appendChild(followStream);
    
    if (dissector.getConnectionsById()[id].contents && 
        (dissector.getConnectionsById()[id].contents[0].length || 
         dissector.getConnectionsById()[id].contents[1].length))
    {
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
    contextMenu.style.left = xPos + 'px';
    contextMenu.style.top = yPos + 'px';
    contextMenu.appendChild(doubleBuffer);
    
    
    return;
}

function closeContextMenu() {
    contextMenu.className = 'hidden'; // it's there, you just dont see it! ;-)
}

function selectRow(num) {
    var selectedRow;
    
    if (packetView)
        selectedPacketRow = num;
    else
        selectedConnectionRow = num;
    
    renderNextTime = true;
}

function processClick(num) {
    selectRow(num);
    
    // which means: this is a packet
    if (packetView || !dissector.getConnectionById(num)) {
        printPacketDetails(num);
        printBytes(num);
        return;
    }
    
    printConnectionDetails(num);
    bytesOutput.innerHTML = '';
}

function processRightClick(num, event, id) {
    processClick(num);
    openContextMenu(id, event.pageX, event.pageY);
    return false;
}

function downloadContent(id, srcOrDst) {
    var data = dissector.getConnectionById(id).getContent(srcOrDst);       
    downloadFileFromURI(createURI('application/x-download', data), id);
}

function showContent(id) {
    var contents = dissector.getConnectionsById()[id].mergeContent();
    
    if (contents.length === 0)
        return;
    
    var data = [];
    var mergedContent;
    var srcOrDst = contents[0].srcOrDst;
        
    var box = document.createElement('div');
    box.className = 'contentbox';
    
    for (var i = 0; i < contents.length; i++) {
        if (srcOrDst !== contents[i].srcOrDst) {
            mergedContent = new Uint8Array(mergeBuffers(data));
            
            var text = '';
            for (var j = 0; j < mergedContent.length; j++)
                text += printASCII(mergedContent[j]);

            var span = document.createElement('span');
            span.className = ((srcOrDst && 'src') || 'dst') + 'content';
            span.appendChild(document.createTextNode(text));
            
            box.appendChild(span);
            
            data = [];
            srcOrDst = contents[i].srcOrDst;
        }
        data.push(contents[i].data.slice(contents[i].offset));
    }
    mergedContent = new Uint8Array(mergeBuffers(data));
    
    var text = '';
    for (var j = 0; j < mergedContent.length; j++)
        text += printASCII(mergedContent[j]);

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
    
    renderThread = window.requestAnimationFrame(render);
}

function switchView() {
    packetView = !packetView;
    renderNextTime = true;
}

function saveCapture() {
    downloadFileFromURI(getPcapURI(dissector), 'log.pcap');
}