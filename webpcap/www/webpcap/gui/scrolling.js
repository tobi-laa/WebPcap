'use strict';

var scrollbarTrack = document.getElementById('scrollbar-track');
var scrollThumb = document.getElementById('scroll-thumb');

var scrollbar = document.getElementById('scrollbar');
var scrollbarButtonUp = document.getElementById('scrollbar-button-up');
var scrollbarButtonDown = document.getElementById('scrollbar-button-down');

var scrollThumbSelected = false;

var initScrollThumbY;
var scrollInterval;
var mouseX;
var mouseY;

var MIN_SCROLLTHUMB_SIZE = 32; // in pixels
var MAX_SCROLLTHUMB_OFFSET; // calculated on resize

function calculateScrollbarSize() {
    var packetNumber = 0;
    var scrollbarTrackStart;
    var scrollbarTrackSize;
    
    if (packetView) {
        packetNumber = packets.length;
        scrollbarTrackStart = packetViewAnchor;
    }
    else {
        var array = connectionViewLength();
        packetNumber = array[0];
        scrollbarTrackStart = array[1];
    }
    
    scrollbarTrackStart = Math.min(scrollbarTrackStart * scrollbarTrack.offsetHeight / packetNumber, MAX_SCROLLTHUMB_OFFSET);
    scrollbarTrackSize = Math.max(maxRows * scrollbarTrack.offsetHeight / packetNumber, MIN_SCROLLTHUMB_SIZE);
    if (scrollbarTrackSize >= scrollbarTrack.offsetHeight || packetNumber === 0) {
        scrollThumb.className = 'hidden';
        scrollbarButtonUp.className = 'scrollbar-button-up-inactive';
        scrollbarButtonDown.className = 'scrollbar-button-down-inactive';
        return;
    }
        
    if (autoscroll) {
        scrollbarButtonUp.className = 'scrollbar-button-up';
        scrollbarButtonDown.className = 'scrollbar-button-down-inactive';
    }
    else {
        scrollbarButtonDown.className = 'scrollbar-button-down';
        // FIXME
        if ((packetView && packetViewAnchor === 0) || (!packetView && connAnchor === 0 && pktAnchor === -1))
            scrollbarButtonUp.className = 'scrollbar-button-up-inactive';
        else
            scrollbarButtonUp.className = 'scrollbar-button-up';
    }
    scrollThumb.className = '';
    scrollThumb.style.height = scrollbarTrackSize + 'px';
    scrollThumb.style.top = scrollbarTrackStart + 'px';
} 

function processMouseWheel(event) {
    event = window.event || event;
    var wheelDelta = event.deltaY ? event.deltaY * 2 : event.wheelDelta / -20;
    scroll(wheelDelta);
    return false;
}

function startScrolling(direction) {
    disableTextSelection();
    clearTimeout(scrollInterval); // stop running scroll process
    scrollInterval = setInterval(function() {scroll(direction);}, 20);
}

function scroll(direction) {
    if (packetView)
        scrollPacketView(direction);
    else
        scrollConnectionView(direction);
}

function scrollPacketView(direction) {
    if (packets.length === 0)
        return;
    
    autoscroll = false;
    renderNextTime = true;
    
    packetViewAnchor += direction;
    
    if (packetViewAnchor < 0)
        packetViewAnchor = 0
    else if (packetViewAnchor >= packets.length - maxRows) {
        // we don't want a negative anchor
        packetViewAnchor = Math.max(packets.length - maxRows, 0);
        autoscroll = true;
    }
}

function startTrackScrolling(init) {
    var relPosY;    
    
    if (init) 
        disableTextSelection();
    
    relPosY = mouseY - scrollbar.offsetTop - scrollbarTrack.offsetTop;
    
    if (relPosY < scrollThumb.offsetTop) {
        scroll(-50);
        scrollInterval = setTimeout(startTrackScrolling, 20);        
    }
    else if (relPosY > scrollThumb.offsetTop + scrollThumb.offsetHeight) {
        scroll(50);
        scrollInterval = setTimeout(startTrackScrolling, 20);        
    }
    else
        clearTimeout(scrollInterval);
}

function selectScrollThumb(event) {
    disableTextSelection();
    scrollThumbSelected = true;
    initScrollThumbY = scrollThumb.offsetTop - event.pageY;
    return false;
}

function disableTextSelection() {
    html.onselectstart = function () {return false;}; // so we don't select text
    html.className = 'defaultcursor';
}

function enableTextSelection() {
    html.onselectstart = null;
    html.className = '';
}

function processMouseUp() {
    scrollThumbSelected = false;
    clearTimeout(scrollInterval);
    enableTextSelection();
    return false;
}

function processMouseMove(event) {
    mouseX = event.pageX;
    mouseY = event.pageY;
    moveScrollThumb(event);
}

function moveScrollThumb(event) {   
    if (!scrollThumbSelected)
        return true;
    
    autoscroll = false;
    
    var newPos = (event.pageY + initScrollThumbY)
                    / scrollbarTrack.offsetHeight;
    
    if (packetView) {
        newPos = (packets.length * newPos) | 0;
        
        if (newPos < 0)
            newPos = 0;
        else if (newPos >= packets.length - maxRows) {
            newPos = packets.length - maxRows;
            autoscroll = true;
        }
        
        packetViewAnchor = newPos;
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