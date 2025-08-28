"""
dom.py
------
Module for comparing DOM snapshots to detect client-side injection or mutation.
Used in active scanning for DOM-based XSS, JS injections, and frontend behavior analysis.
"""

from typing import Dict, List
import difflib
import hashlib
import json


class DOMDiff:
    def __init__(self, base_dom: str, test_dom: str):
        """
        base_dom: DOM snapshot of the original page
        test_dom: DOM snapshot after test payload injection
        """
        self.base_dom = base_dom
        self.test_dom = test_dom

    def compare_hash(self) -> Dict:
        """Compare DOMs using SHA256 hash."""
        base_hash = hashlib.sha256(self.base_dom.encode()).hexdigest()
        test_hash = hashlib.sha256(self.test_dom.encode()).hexdigest()
        return {
            "match": base_hash == test_hash,
            "base_hash": base_hash,
            "test_hash": test_hash
        }

    def compare_diff(self) -> Dict:
        """Return unified diff of DOM snapshots."""
        diff = list(difflib.unified_diff(
            self.base_dom.splitlines(),
            self.test_dom.splitlines(),
            fromfile="base_dom",
            tofile="test_dom",
            lineterm=''
        ))
        return {
            "diff": diff,
            "is_different": bool(diff)
        }

    def compare_json_structure(self) -> Dict:
        """
        Compare DOM as parsed JSON structure.
        Useful if DOM is exported as JSON (e.g., from puppeteer/playwright)
        """
        try:
            base_json = json.loads(self.base_dom)
            test_json = json.loads(self.test_dom)
        except json.JSONDecodeError:
            return {"error": "DOM is not valid JSON"}

        differences = []

        def recursive_diff(base, test, path="root"):
            if type(base) != type(test):
                differences.append({"path": path, "base_type": str(type(base)), "test_type": str(type(test))})
                return
            if isinstance(base, dict):
                for key in set(base.keys()).union(test.keys()):
                    recursive_diff(base.get(key), test.get(key), path + f".{key}")
            elif isinstance(base, list):
                for i, (b, t) in enumerate(zip(base, test)):
                    recursive_diff(b, t, path + f"[{i}]")
            else:
                if base != test:
                    differences.append({"path": path, "base": base, "test": test})

        recursive_diff(base_json, test_json)
        return {"differences": differences, "is_different": bool(differences)}

    def summary(self) -> Dict:
        """Combined summary of DOM differences."""
        return {
            "hash_match": self.compare_hash(),
            "diff": self.compare_diff(),
            "json_structure": self.compare_json_structure()
        }


if __name__ == "__main__":
    # Example usage
    base_dom_snapshot = "<html><body><div>Hello</div></body></html>"
    test_dom_snapshot = "<html><body><div>Hello world!</div></body></html>"

    dom_diff = DOMDiff(base_dom_snapshot, test_dom_snapshot)
    result = dom_diff.summary()
    print(result)
