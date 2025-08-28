// dom_markers.js
(function() {
    // Store all potential XSS sinks and sensitive DOM nodes
    if (!window._scanDomMarkers) {
        window._scanDomMarkers = [];
    }

    /**
     * Checks if a string contains suspicious HTML or JS code
     * that could be an XSS injection vector.
     */
    function isSuspicious(value) {
        if (!value || typeof value !== 'string') return false;
        const patterns = [
            /<script.*?>/i,
            /javascript:/i,
            /on\w+\s*=/i,
            /<img.*?onerror/i,
            /<iframe/i
        ];
        return patterns.some(pattern => pattern.test(value));
    }

    /**
     * Traverse DOM and collect nodes with potential XSS sinks
     */
    function scanDOM() {
        const elements = document.querySelectorAll('*');
        elements.forEach(el => {
            const attrs = el.attributes;
            for (let i = 0; i < attrs.length; i++) {
                const attr = attrs[i];
                if (isSuspicious(attr.value)) {
                    window._scanDomMarkers.push({
                        tag: el.tagName,
                        type: 'attribute',
                        name: attr.name,
                        value: attr.value,
                        path: getDomPath(el)
                    });
                }
            }

            // Check innerHTML for potential script injections
            if (isSuspicious(el.innerHTML)) {
                window._scanDomMarkers.push({
                    tag: el.tagName,
                    type: 'innerHTML',
                    value: el.innerHTML,
                    path: getDomPath(el)
                });
            }
        });
    }

    /**
     * Generate a unique DOM path for an element
     */
    function getDomPath(el) {
        if (!el) return '';
        const stack = [];
        while (el.parentNode != null) {
            let sibCount = 0;
            let sibIndex = 0;
            const siblings = el.parentNode.childNodes;
            for (let i = 0; i < siblings.length; i++) {
                const sib = siblings[i];
                if (sib.nodeName === el.nodeName) {
                    if (sib === el) sibIndex = sibCount;
                    sibCount++;
                }
            }
            stack.unshift(`${el.nodeName}:nth-of-type(${sibIndex + 1})`);
            el = el.parentNode;
        }
        return stack.join(' > ');
    }

    // Run scan immediately and also after DOM content loaded
    scanDOM();
    document.addEventListener('DOMContentLoaded', scanDOM);

    console.log("[DOM Markers] Scan completed. Potential XSS sinks:", window._scanDomMarkers);
})();
