var scheme = window.location.protocol === "https:" ? "wss://" : "ws://";

var styles = {};

var codes = {
    // reset: [0, 0],
    //
    // bold: [1, 22],
    // dim: [2, 22],
    // italic: [3, 23],
    // underline: [4, 24],
    // inverse: [7, 27],
    // hidden: [8, 28],
    // strikethrough: [9, 29],

    black: [30, 39],
    red: [31, 39],
    green: [32, 39],
    yellow: [33, 39],
    blue: [34, 39],
    magenta: [35, 39],
    cyan: [36, 39],
    white: [37, 39],
    gray: [90, 39],
    grey: [90, 39],

    // bgBlack: [40, 49],
    // bgRed: [41, 49],
    // bgGreen: [42, 49],
    // bgYellow: [43, 49],
    // bgBlue: [44, 49],
    // bgMagenta: [45, 49],
    // bgCyan: [46, 49],
    // bgWhite: [47, 49],
    //
    // // legacy styles for colors pre v1.0.0
    // blackBG: [40, 49],
    // redBG: [41, 49],
    // greenBG: [42, 49],
    // yellowBG: [43, 49],
    // blueBG: [44, 49],
    // magentaBG: [45, 49],
    // cyanBG: [46, 49],
    // whiteBG: [47, 49],
};

var entityMap = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '/': '&#x2F;',
    '`': '&#x60;',
    '=': '&#x3D;'
};

function escapeHtml(string) {
    return String(string).replace(/[&<>"'`=\/]/g, function (s) {
        return entityMap[s];
    });
}

Object.keys(codes).forEach(function(key) {
    var val = codes[key];
    var style = styles[key] = [];
    style.open = '\u001b[' + val[0] + 'm';
    style.close = '\u001b[' + val[1] + 'm';
});

$(function() {
    Terminal.applyAddon(fullscreen);
    Terminal.applyAddon(fit);
    Terminal.applyAddon(attach);
    Terminal.applyAddon({
        "__esModule": { value: true },
        apply: function(terminalConstructor) {
            terminalConstructor.prototype.showOverlay = function (msg, timeout) {
                return showOverlay(this, msg, timeout);
            };
        },
        showOverlay
    });
});

function showOverlay(term, msg, timeout) {
    if (!term.overlayNode_) {
        if (!term.element)
            return;
        term.overlayNode_ = document.createElement('div');
        term.overlayNode_.style.cssText = (
            'border-radius: 15px;' +
            'font-size: xx-large;' +
            'opacity: 0.75;' +
            'padding: 0.2em 0.5em 0.2em 0.5em;' +
            'position: absolute;' +
            '-webkit-user-select: none;' +
            '-webkit-transition: opacity 180ms ease-in;' +
            '-moz-user-select: none;' +
            '-moz-transition: opacity 180ms ease-in;');

        term.overlayNode_.addEventListener('mousedown', function(e) {
            e.preventDefault();
            e.stopPropagation();
        }, true);
    }
    term.overlayNode_.style.color = "#101010";
    term.overlayNode_.style.backgroundColor = "#f0f0f0";

    term.overlayNode_.textContent = msg;
    term.overlayNode_.style.opacity = '0.75';

    if (!term.overlayNode_.parentNode)
        term.element.appendChild(term.overlayNode_);

    var divSize = term.element.getBoundingClientRect();
    var overlaySize = term.overlayNode_.getBoundingClientRect();

    term.overlayNode_.style.top =
        (divSize.height - overlaySize.height) / 2 + 'px';
    term.overlayNode_.style.left = (divSize.width - overlaySize.width) / 2 + 'px';

    if (term.overlayTimeout_)
        clearTimeout(term.overlayTimeout_);

    if (timeout === null)
        return;

    term.overlayTimeout_ = setTimeout(function() {
        term.overlayNode_.style.opacity = '0';
        term.overlayTimeout_ = setTimeout(function() {
            if (term.overlayNode_.parentNode)
                term.overlayNode_.parentNode.removeChild(term.overlayNode_);
            term.overlayTimeout_ = null;
            term.overlayNode_.style.opacity = '0.75';
        }, 200);
    }, timeout || 1500);
}

function createTerminal() {
    var term = new Terminal({
        cursorBlink: true,
        fontSize: 13,
        fontFamily: '"Menlo for Powerline", Menlo, Consolas, "Liberation Mono", Courier, monospace',
        rows: Math.floor((window.innerHeight - 28)/15.5),
        theme: {
            foreground: '#d2d2d2',
            cursor: '#adadad',
            black: '#000000',
            red: '#d81e00',
            green: '#5ea702',
            yellow: '#cfae00',
            blue: '#427ab3',
            magenta: '#89658e',
            cyan: '#00a7aa',
            white: '#dbded8',
            brightBlack: '#686a66',
            brightRed: '#f54235',
            brightGreen: '#99e343',
            brightYellow: '#fdeb61',
            brightBlue: '#84b0d8',
            brightMagenta: '#bc94b7',
            brightCyan: '#37e6e8',
            brightWhite: '#f1f1f0'
        }
    });

    term.on('resize', function(size) {
        setTimeout(function() {
            term.showOverlay(size.cols + 'x' + size.rows);
        }, 500);
    });

    term.on('title', function (data) {
        if (data && data !== '') {
            document.title = (data + ' | ' + title);
        }
    });

    window.addEventListener('resize', function() {
        clearTimeout(window.resizedFinished);
        window.resizedFinished = setTimeout(function () {
            term.fit();
            term.resize(term.cols, Math.floor((window.innerHeight - 28)/15.5));
        }, 250);
    });

    term.open(document.getElementById("terminal-container"), true);
    term.toggleFullScreen(true);
    term.fit();
    term.resize(term.cols, Math.floor((window.innerHeight - 28)/15.5));
    term.focus();

    return term;
}