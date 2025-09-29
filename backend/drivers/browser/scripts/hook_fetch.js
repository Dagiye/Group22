// hook_fetch.js
(function() {
    // Keep a reference to the original fetch function
    const originalFetch = window.fetch;

    // Override global fetch
    window.fetch = async function(input, init) {
        const method = (init && init.method) || 'GET';
        const url = (typeof input === 'string') ? input : input.url;
        const startTime = Date.now();

        try {
            const response = await originalFetch(input, init);
            const duration = Date.now() - startTime;

            // Clone response to read body without consuming original
            const clonedResponse = response.clone();
            const responseText = await clonedResponse.text();

            console.log(`[Fetch Hook] ${method} ${url} -> Status: ${response.status} in ${duration}ms`);

            // Store logs for scanner
            if (!window._scanFetchLog) {
                window._scanFetchLog = [];
            }

            window._scanFetchLog.push({
                method: method,
                url: url,
                status: response.status,
                duration: duration,
                response: responseText
            });

            return response;
        } catch (error) {
            console.error(`[Fetch Hook] ${method} ${url} -> Error: ${error}`);
            throw error;
        }
    };

    // Initialize log array if not already
    if (!window._scanFetchLog) {
        window._scanFetchLog = [];
    }

    console.log("[Fetch Hook] Fetch API hooked successfully.");
})();
