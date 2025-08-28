"""
timing.py
---------
Module for detecting time-based differences in responses.
Used in active scanning for blind injections (SQLi, SSRF) or performance anomalies.
"""

import time
import statistics
from typing import List, Dict


class TimingAnalyzer:
    def __init__(self, baseline_response_times: List[float]):
        """
        baseline_response_times: list of response times (in seconds) for normal requests
        """
        self.baseline = baseline_response_times
        self.baseline_mean = statistics.mean(self.baseline) if self.baseline else 0
        self.baseline_std = statistics.stdev(self.baseline) if len(self.baseline) > 1 else 0

    def is_delayed(self, response_time: float, threshold: float = 3.0) -> bool:
        """
        Determines if a response time is delayed compared to baseline.
        threshold: multiplier of standard deviation or seconds to consider as delay
        """
        if not self.baseline:
            return False

        # Using standard deviation based detection
        deviation = abs(response_time - self.baseline_mean)
        if self.baseline_std > 0:
            return deviation > self.baseline_std * threshold
        else:
            # fallback to simple threshold in seconds
            return deviation > threshold

    def analyze_multiple(self, response_times: List[float], threshold: float = 3.0) -> Dict:
        """
        Analyze multiple response times and mark delayed ones.
        """
        results = []
        for t in response_times:
            delayed = self.is_delayed(t, threshold)
            results.append({"response_time": t, "delayed": delayed})
        return {
            "baseline_mean": self.baseline_mean,
            "baseline_std": self.baseline_std,
            "analysis": results
        }


if __name__ == "__main__":
    # Example usage
    baseline_times = [0.1, 0.12, 0.09, 0.11, 0.1]
    test_times = [0.1, 0.11, 0.1, 3.5, 0.12]

    analyzer = TimingAnalyzer(baseline_times)
    report = analyzer.analyze_multiple(test_times)
    print(report)
