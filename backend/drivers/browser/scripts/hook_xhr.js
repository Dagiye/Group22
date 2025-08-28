// hook_xhr.js
(function() {
    const OriginalXHR = window.XMLHttpRequest;

    function CustomXHR() {
        const xhrInstance = new OriginalXHR();

        // Store original open method
        const originalOpen = xhrInstance.open;
        xhrInstance.open = function(method, url, async, user, password) {
            this._method = method;
            this._url = url;

            // Call the original open method
            return originalOpen.apply(this, arguments);
        };

        // Store original send method
        const originalSend = xhrInstance.send;
        xhrInstance.send = function(body) {
            const startTime = Date.now();

            // Listen for state changes
            this.addEventListener('readystatechange', () => {
                if (this.readyState === 4) { // DONE
                    const duration = Date.now() - startTime;
                    console.log(`[XHR Hook] ${this._method} ${this._url} -> Status: ${this.status} in ${duration}ms`);
                    
                    // Here, you could also send the data to your backend or store in memory for scanning
                    if (window._scanXHRLog) {
                        window._scanXHRLog.push({
                            method: this._method,
                            url: this._url,
                            status: this.status,
                            duration: duration,
                            response: this.responseText
                        });
                    }
                }
            });

            return originalSend.apply(this, arguments);
        };

        return xhrInstance;
    }

    // Replace global XMLHttpRequest
    window.XMLHttpRequest = CustomXHR;

    // Initialize scan log array if not already
    if (!window._scanXHRLog) {
        window._scanXHRLog = [];
    }

    console.log("[XHR Hook] XMLHttpRequest hooked successfully.");
})();
