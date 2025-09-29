# backend/drivers/http/dns.py

import dns.resolver
import dns.exception
from typing import List, Optional

class DNSClient:
    """
    DNS client for resolving domains, checking subdomains, and validating responses.
    """

    def __init__(self, nameservers: Optional[List[str]] = None, timeout: float = 3.0):
        """
        :param nameservers: Optional list of DNS servers to use for queries.
        :param timeout: Timeout in seconds for DNS queries.
        """
        self.resolver = dns.resolver.Resolver()
        if nameservers:
            self.resolver.nameservers = nameservers
        self.resolver.lifetime = timeout

    def resolve(self, domain: str, record_type: str = "A") -> List[str]:
        """
        Resolve a domain for a specific record type (A, AAAA, CNAME, MX, etc.)
        :return: List of resolved IPs or hostnames
        """
        results = []
        try:
            answers = self.resolver.resolve(domain, record_type)
            for rdata in answers:
                results.append(rdata.to_text())
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
            pass  # Could log this if needed
        return results

    def check_subdomains(self, base_domain: str, subdomains: List[str], record_type: str = "A") -> List[str]:
        """
        Check a list of subdomains for a base domain.
        Returns the list of valid subdomains that resolved successfully.
        """
        valid = []
        for sub in subdomains:
            full_domain = f"{sub}.{base_domain}"
            if self.resolve(full_domain, record_type):
                valid.append(full_domain)
        return valid

    def mx_records(self, domain: str) -> List[str]:
        """
        Get MX records for a domain.
        """
        return self.resolve(domain, "MX")

    def cname_record(self, domain: str) -> Optional[str]:
        """
        Get CNAME record for a domain.
        """
        result = self.resolve(domain, "CNAME")
        return result[0] if result else None

    def txt_records(self, domain: str) -> List[str]:
        """
        Get TXT records for a domain.
        """
        return self.resolve(domain, "TXT")
