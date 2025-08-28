// xss_sink_map.js
(function() {
    // Global object to store all XSS sinks detected during scanning
    if (!window._xssSinkMap) {
        window._xssSinkMap = [];
    }

    /**
     * Add a new sink to the global map
     * @param {Object} sink - Details of the potential XSS sink
     * @param {string} sink.type - Type: 'xhr', 'fetch', 'dom', etc.
     * @param {string} sink.location - Where it was found (URL, DOM path)
     * @param {string} sink.value - Payload or data triggering the sink
     * @param {string} [sink.extra] - Optional extra info
     */
    function addSink(sink) {
        if (!sink || !sink.type || !sink.location) return;
        window._xssSinkMap.push(sink);
    }

    /**
     * Hook XMLHttpRequest to capture potential XSS payloads
     */
    const origXHR = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
        this.addEventListener('load', function() {
            if (this.responseText && this.responseText.includes('<script')) {
                addSink({
                    type: 'xhr',
                    location: url,
                    value: this.responseText
                });
            }
        });
        return origXHR.apply(this, arguments);
    };

    /**
     * Hook fetch to capture XSS-like responses
     */
    const origFetch = window.fetch;
    window.fetch = function(input, init) {
        return origFetch(input, init).then(response => {
            response.clone().text().then(text => {
                if (text.includes('<script')) {
                    addSink({
                        type: 'fetch',
                        location: input,
                        value: text
                    });
                }
            });
            return response;
        });
    };

    /**
     * Capture DOM-based XSS markers from the previous scan
     */
    if (window._scanDomMarkers && window._scanDomMarkers.length > 0) {
        window._scanDomMarkers.forEach(marker => {
            addSink({
                type: 'dom',
                location: marker.path,
                value: marker.value,
                extra: marker.name || ''
            });
        });
    }

    console.log("[XSS Sink Map] Mapping completed. Total sinks:", window._xssSinkMap.length);
})();
