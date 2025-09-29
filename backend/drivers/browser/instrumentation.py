# backend/drivers/browser/instrumentation.py

from typing import Dict, Any
from playwright.async_api import Page
import asyncio
import json


class BrowserInstrumentation:
    """
    Injects JavaScript hooks into a webpage to capture:
      - XHR and fetch requests
      - DOM mutations
      - Form submissions
      - Potential XSS sink points
    """

    def __init__(self, page: Page):
        self.page = page
        self.collected_data = {
            "xhr": [],
            "fetch": [],
            "dom_mutations": [],
            "form_submissions": []
        }

    async def inject_hooks(self):
        """
        Injects all JavaScript hooks into the page.
        """
        await asyncio.gather(
            self._inject_xhr_hook(),
            self._inject_fetch_hook(),
            self._inject_dom_hook(),
            self._inject_form_hook()
        )

    async def _inject_xhr_hook(self):
        """
        Hook XHR requests and responses.
        """
        script = """
        (function() {
            const origOpen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function(method, url) {
                this.addEventListener('load', function() {
                    window.__playwright_data = window.__playwright_data || {xhr: []};
                    window.__playwright_data.xhr.push({method, url, status: this.status, response: this.responseText});
                });
                return origOpen.apply(this, arguments);
            };
        })();
        """
        await self.page.add_init_script(script)

    async def _inject_fetch_hook(self):
        """
        Hook fetch requests and responses.
        """
        script = """
        (function() {
            const origFetch = window.fetch;
            window.fetch = async function(input, init) {
                const response = await origFetch(input, init);
                const clone = response.clone();
                clone.text().then(body => {
                    window.__playwright_data = window.__playwright_data || {fetch: []};
                    window.__playwright_data.fetch.push({
                        url: input,
                        status: response.status,
                        response: body
                    });
                });
                return response;
            };
        })();
        """
        await self.page.add_init_script(script)

    async def _inject_dom_hook(self):
        """
        Hook DOM mutations to track dynamic changes.
        """
        script = """
        (function() {
            const observer = new MutationObserver(mutations => {
                window.__playwright_data = window.__playwright_data || {dom_mutations: []};
                mutations.forEach(mutation => {
                    window.__playwright_data.dom_mutations.push({
                        type: mutation.type,
                        target: mutation.target.outerHTML
                    });
                });
            });
            observer.observe(document, { attributes: true, childList: true, subtree: true });
        })();
        """
        await self.page.add_init_script(script)

    async def _inject_form_hook(self):
        """
        Hook form submissions.
        """
        script = """
        (function() {
            document.addEventListener('submit', function(e) {
                window.__playwright_data = window.__playwright_data || {form_submissions: []};
                const form = e.target;
                const data = {};
                new FormData(form).forEach((value, key) => { data[key] = value });
                window.__playwright_data.form_submissions.push({action: form.action, method: form.method, data});
            }, true);
        })();
        """
        await self.page.add_init_script(script)

    async def collect_data(self) -> Dict[str, Any]:
        """
        Retrieve collected data from the page.
        """
        data = await self.page.evaluate("window.__playwright_data || {}")
        return data
