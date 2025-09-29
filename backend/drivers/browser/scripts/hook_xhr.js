/**
 * XHR Hook Script
 *
 * This script monkey-patches XMLHttpRequest to capture all XHR requests/responses.
 * It sends the data back to the backend via window.__captureXHR (injected by Python/Playwright).
 *
 * Usage:
 *   Inject this script in browser context before scanning starts.
 */

(function() {
    if (window.__xhrHookInstalled) return;
    window.__xhrHookInstalled = true;

    const originalXHR = window.XMLHttpRequest;

    function CustomXHR() {
        const xhr = new originalXHR();

        const sendOrig = xhr.send;
        xhr.send = function(body) {
            xhr.addEventListener("loadend", function() {
                try {
                    if (window.__captureXHR) {
                        window.__captureXHR({
                            method: xhr._method || "GET",
                            url: xhr._url || xhr.responseURL,
                            status: xhr.status,
                            requestBody: body,
                            responseBody: xhr.response
                        });
                    }
                } catch (e) {
                    console.error("XHR capture error", e);
                }
            });
            sendOrig.call(xhr, body);
        };

        const openOrig = xhr.open;
        xhr.open = function(method, url) {
            xhr._method = method;
            xhr._url = url;
            return openOrig.apply(xhr, arguments);
        };

        return xhr;
    }

    window.XMLHttpRequest = CustomXHR;
})();
