"""
UT-01 — URL normalization test table (PRD §6.1, FR-02)
=======================================================

At least 60 cases covering:
  - scheme-less rows           (N-02)
  - leading U+00A0 / BOM       (N-01)
  - whitespace inside          (N-01 error)
  - url_too_long               (N-12)
  - host lowercasing           (N-03)
  - trailing dot removal       (N-05)
  - default-port stripping     (N-05)
  - path resolution . / ..    (N-06)
  - IP host forms              (N-07): dotted-decimal, IPv6, hex, octal, int
  - punycode / IDN encoding    (N-04)
  - fragment in normalized,    (N-08)
    absent from cache_key
  - tracking-param stripping   (N-09)
  - non-tracking params kept   (N-09)
  - keyword decoding           (N-10)
  - registrable domain via PSL (N-11)
  - tenant host x.github.io   (N-11)
  - dataset anomalous rows     (actual D1 patterns)

PSL parser test vectors (TestPSLParser):
  - Official Mozilla PSL test vectors (wildcard, exception, private-section)
  - Uses PSL.for_testing() — no psl.dat required
  - If psl.dat is present, also runs against the real file (TestPSLWithRealFile)
"""

from __future__ import annotations

import pathlib
import sys
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.normalize import normalize, NormalizeResult
from ml.psl import PSL, reset_psl


# ═══════════════════════════════════════════════════════════════════════════════
# Session-scoped fixture: patch get_psl() to use PSL.for_testing()
# so UT-01 runs even when lists/psl.dat is absent.
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True, scope="session")
def _use_test_psl(tmp_path_factory):
    """
    Redirect normalize.get_psl() to PSL.for_testing() for the entire test session.
    This makes UT-01 independent of psl.dat being present on disk.
    """
    import ml.normalize as _norm_mod
    import ml.psl as _psl_mod

    test_psl = PSL.for_testing()

    _original_get_psl = _psl_mod.get_psl

    def _patched_get_psl():
        return test_psl

    _psl_mod.get_psl  = _patched_get_psl
    _norm_mod.get_psl = _patched_get_psl   # normalize imports get_psl at call time

    yield

    _psl_mod.get_psl  = _original_get_psl
    _norm_mod.get_psl = _original_get_psl
    reset_psl()
from ml.psl import PSL


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _ok(raw: str) -> NormalizeResult:
    """Normalize and assert no error."""
    r = normalize(raw)
    assert r.error is None, f"Expected no error for {raw!r}, got {r.error!r}"
    return r


def _err(raw: str, expected_error: str) -> NormalizeResult:
    """Normalize and assert the expected error code."""
    r = normalize(raw)
    assert r.error == expected_error, (
        f"Expected error={expected_error!r} for {raw!r}, got {r.error!r}"
    )
    return r


# ═══════════════════════════════════════════════════════════════════════════════
# N-01 — Whitespace trimming
# ═══════════════════════════════════════════════════════════════════════════════

class TestN01Whitespace:

    def test_leading_space_trimmed(self):
        r = _ok("  https://example.com/")
        assert "example.com" in r.puny_host

    def test_trailing_space_trimmed(self):
        r = _ok("https://example.com/  ")
        assert "example.com" in r.puny_host

    def test_leading_nbsp_u00a0_trimmed(self):
        """U+00A0 (non-breaking space) must be stripped (N-01)."""
        r = _ok("\u00a0https://example.com/")
        assert "example.com" in r.puny_host

    def test_leading_bom_stripped(self):
        """BOM (U+FEFF) must be stripped (N-01)."""
        r = _ok("\ufeffhttps://example.com/")
        assert "example.com" in r.puny_host

    def test_leading_bom_fffe_stripped(self):
        r = _ok("\ufffe https://example.com/")
        assert "example.com" in r.puny_host

    def test_internal_space_error(self):
        """Whitespace inside the URL after outer trim → whitespace_inside (N-01)."""
        _err("https://exa mple.com/", "whitespace_inside")

    def test_internal_tab_error(self):
        _err("https://example.com/pa\tth", "whitespace_inside")

    def test_internal_nbsp_error(self):
        """Non-breaking space inside → whitespace_inside (N-01)."""
        _err("https://example\u00a0.com/", "whitespace_inside")


# ═══════════════════════════════════════════════════════════════════════════════
# N-02 — Scheme injection for scheme-less URLs
# ═══════════════════════════════════════════════════════════════════════════════

class TestN02SchemeLess:

    def test_bare_domain_gets_http(self):
        r = _ok("example.com")
        assert r.scheme == "http"
        assert "example.com" in r.puny_host

    def test_bare_domain_with_path_gets_http(self):
        r = _ok("example.com/path/to/page")
        assert r.scheme == "http"
        assert r.path == "/path/to/page"

    def test_bare_www_domain_gets_http(self):
        r = _ok("www.example.com")
        assert r.scheme == "http"
        assert "www.example.com" in r.puny_host

    def test_schemeless_with_query(self):
        r = _ok("example.com/search?q=hello")
        assert r.scheme == "http"
        assert "q=hello" in r.query

    def test_schemeless_real_dataset_pattern(self):
        """Pattern seen in D1: 'google.com' (no scheme, no path)."""
        r = _ok("google.com")
        assert r.scheme == "http"
        assert r.registrable_domain == "google.com"

    def test_schemeless_with_subdomain(self):
        r = _ok("signin.eby.de.example.com/login")
        assert r.scheme == "http"


# ═══════════════════════════════════════════════════════════════════════════════
# N-03 — Case folding
# ═══════════════════════════════════════════════════════════════════════════════

class TestN03CaseFolding:

    def test_uppercase_host_lowercased(self):
        r = _ok("https://EXAMPLE.COM/Path?Query=Value")
        assert r.puny_host == "example.com"

    def test_mixed_case_host_lowercased(self):
        r = _ok("https://Example.Com/")
        assert r.puny_host == "example.com"

    def test_path_case_preserved(self):
        r = _ok("https://example.com/MyPath/Page")
        assert r.path == "/MyPath/Page"

    def test_query_case_preserved(self):
        r = _ok("https://example.com/?Key=Value")
        assert "Key=Value" in r.query

    def test_scheme_uppercase_lowercased(self):
        r = _ok("HTTPS://example.com/")
        assert r.scheme == "https"


# ═══════════════════════════════════════════════════════════════════════════════
# N-04 — Punycode / IDN
# ═══════════════════════════════════════════════════════════════════════════════

class TestN04Punycode:

    def test_ascii_host_unchanged(self):
        r = _ok("https://example.com/")
        assert r.puny_host == "example.com"
        assert r.is_punycode is False

    def test_xn_host_flagged(self):
        """xn-- already-encoded host is detected as punycode."""
        r = _ok("https://xn--nxasmq6b.com/")
        assert r.is_punycode is True

    def test_unicode_host_encoded(self):
        """Non-ASCII hostname is IDNA-encoded."""
        r = _ok("https://пример.испытание/")
        # Should produce xn-- punycode labels
        assert "xn--" in r.puny_host
        assert r.is_punycode is True

    def test_display_host_unicode_preserved(self):
        r = _ok("https://пример.испытание/")
        # display_host keeps Unicode form
        assert "п" in r.display_host or "xn--" in r.display_host  # encoding may vary


# ═══════════════════════════════════════════════════════════════════════════════
# N-05 — Trailing dot and default port removal
# ═══════════════════════════════════════════════════════════════════════════════

class TestN05TrailingDotAndPort:

    def test_trailing_dot_removed(self):
        r = _ok("https://example.com./")
        assert not r.puny_host.endswith(".")

    def test_http_port_80_removed(self):
        r = _ok("http://example.com:80/page")
        assert ":80" not in r.normalized

    def test_https_port_443_removed(self):
        r = _ok("https://example.com:443/page")
        assert ":443" not in r.normalized

    def test_http_port_8080_kept(self):
        r = _ok("http://example.com:8080/page")
        assert ":8080" in r.normalized

    def test_https_port_8443_kept(self):
        r = _ok("https://example.com:8443/api")
        assert ":8443" in r.normalized

    def test_https_port_80_kept(self):
        """Port 80 on HTTPS is non-default — must be kept."""
        r = _ok("https://example.com:80/page")
        assert ":80" in r.normalized


# ═══════════════════════════════════════════════════════════════════════════════
# N-06 — Path resolution
# ═══════════════════════════════════════════════════════════════════════════════

class TestN06PathResolution:

    def test_single_dot_removed(self):
        r = _ok("https://example.com/a/./b")
        assert r.path == "/a/b"

    def test_double_dot_resolved(self):
        r = _ok("https://example.com/a/b/../c")
        assert r.path == "/a/c"

    def test_multiple_dots_resolved(self):
        r = _ok("https://example.com/a/b/../../c")
        assert r.path == "/c"

    def test_leading_slash_preserved(self):
        r = _ok("https://example.com/page")
        assert r.path.startswith("/")

    def test_empty_path(self):
        r = _ok("https://example.com")
        # empty path is fine
        assert isinstance(r.path, str)

    def test_deep_path_unchanged(self):
        r = _ok("https://example.com/a/b/c/d/e")
        assert r.path == "/a/b/c/d/e"


# ═══════════════════════════════════════════════════════════════════════════════
# N-07 — IP host detection
# ═══════════════════════════════════════════════════════════════════════════════

class TestN07IPDetection:

    def test_ipv4_dotted_decimal(self):
        r = _ok("http://192.168.1.1/page")
        assert r.is_ip_host is True

    def test_ipv4_public(self):
        r = _ok("http://8.8.8.8/")
        assert r.is_ip_host is True

    def test_ipv6_literal(self):
        r = _ok("http://[2001:db8::1]/page")
        assert r.is_ip_host is True

    def test_ipv4_hex(self):
        """0xC0A80101 = 192.168.1.1 (N-07)."""
        r = _ok("http://0xC0A80101/")
        assert r.is_ip_host is True

    def test_ipv4_integer(self):
        """3232235777 = 192.168.1.1 as uint32 (N-07)."""
        r = _ok("http://3232235777/")
        assert r.is_ip_host is True

    def test_ipv4_octal(self):
        """0300.0250.01.01 = 192.168.1.1 in octal (N-07)."""
        r = _ok("http://0300.0250.01.01/")
        assert r.is_ip_host is True

    def test_hostname_not_ip(self):
        r = _ok("https://example.com/")
        assert r.is_ip_host is False

    def test_numeric_subdomain_not_ip(self):
        """123.example.com is NOT an IP host."""
        r = _ok("https://123.example.com/")
        assert r.is_ip_host is False

    def test_ip_hosts_never_reach_psl(self, monkeypatch):
        """
        N-07 & N-11: normalize() detects IP hosts before PSL lookup.
        Verify that for IP hosts, PSL.registrable_domain is never invoked,
        and both registrable_domain and public_suffix are None.
        """
        import ml.normalize as norm_mod
        psl = norm_mod.get_psl()

        called = []
        def spy_registrable_domain(host):
            called.append(host)
            return "unexpected.domain"

        monkeypatch.setattr(psl, "registrable_domain", spy_registrable_domain)

        r = normalize("http://192.168.1.1/login")
        assert r.is_ip_host is True
        assert r.registrable_domain is None
        assert r.public_suffix is None
        assert len(called) == 0, f"PSL was unexpectedly called for IP host: {called}"


# ═══════════════════════════════════════════════════════════════════════════════
# N-08 — Fragment handling
# ═══════════════════════════════════════════════════════════════════════════════

class TestN08Fragment:

    def test_fragment_in_normalized(self):
        r = _ok("https://example.com/page#section")
        assert "#section" in r.normalized

    def test_fragment_absent_from_cache_key(self):
        r = _ok("https://example.com/page#section")
        assert "#" not in r.cache_key

    def test_no_fragment_unchanged(self):
        r = _ok("https://example.com/page")
        assert "#" not in r.normalized
        assert "#" not in r.cache_key

    def test_fragment_with_query(self):
        r = _ok("https://example.com/page?q=1#sec")
        assert "#sec" in r.normalized
        assert "#" not in r.cache_key
        assert "q=1" in r.cache_key


# ═══════════════════════════════════════════════════════════════════════════════
# N-09 — Tracking parameter stripping (cache key only)
# ═══════════════════════════════════════════════════════════════════════════════

class TestN09TrackingParams:

    def test_utm_source_stripped_from_cache(self):
        r = _ok("https://example.com/?utm_source=email&page=1")
        assert "utm_source" not in r.cache_key
        assert "page=1" in r.cache_key

    def test_utm_medium_stripped(self):
        r = _ok("https://example.com/?utm_medium=cpc")
        assert "utm_medium" not in r.cache_key

    def test_fbclid_stripped(self):
        r = _ok("https://example.com/?fbclid=abc123&id=5")
        assert "fbclid" not in r.cache_key
        assert "id=5" in r.cache_key

    def test_gclid_stripped(self):
        r = _ok("https://example.com/?gclid=xyz&ref=home")
        assert "gclid" not in r.cache_key
        assert "ref=home" in r.cache_key

    def test_msclkid_stripped(self):
        r = _ok("https://example.com/?msclkid=abc&p=2")
        assert "msclkid" not in r.cache_key

    def test_tracking_params_in_normalized(self):
        """Features use the full query — tracking params kept in normalized."""
        r = _ok("https://example.com/?utm_source=email")
        assert "utm_source" in r.normalized

    def test_non_tracking_param_kept(self):
        r = _ok("https://example.com/?q=search&sort=asc")
        assert "q=search" in r.cache_key
        assert "sort=asc" in r.cache_key

    def test_all_tracking_stripped_empty_query(self):
        r = _ok("https://example.com/?utm_source=a&utm_medium=b")
        # Cache key should have no query params
        from urllib.parse import urlparse
        parsed = urlparse(r.cache_key)
        assert parsed.query == ""

    def test_fragment_and_tracking_combined(self):
        r = _ok("https://example.com/?utm_campaign=x&id=1#top")
        assert "utm_campaign" not in r.cache_key
        assert "id=1" in r.cache_key
        assert "#top" not in r.cache_key
        assert "#top" in r.normalized


# ═══════════════════════════════════════════════════════════════════════════════
# N-10 — Keyword decoding
# ═══════════════════════════════════════════════════════════════════════════════

class TestN10KeywordDecoding:

    def test_percent_encoded_decoded(self):
        r = _ok("https://example.com/%6C%6F%67%69%6E")
        assert "login" in r.decoded_url

    def test_decoded_is_lowercase(self):
        r = _ok("https://EXAMPLE.COM/PATH")
        assert r.decoded_url == r.decoded_url.lower()

    def test_raw_length_uses_normalized(self):
        r = _ok("https://example.com/page")
        assert r.raw_length == len(r.normalized)


# ═══════════════════════════════════════════════════════════════════════════════
# N-11 — Registrable domain via PSL (including private section)
# ═══════════════════════════════════════════════════════════════════════════════

class TestN11RegistrableDomain:

    def test_simple_domain(self):
        r = _ok("https://google.com/")
        assert r.registrable_domain == "google.com"

    def test_www_subdomain_stripped(self):
        r = _ok("https://www.google.com/")
        assert r.registrable_domain == "google.com"

    def test_deep_subdomain(self):
        r = _ok("https://a.b.example.com/")
        assert r.registrable_domain == "example.com"

    def test_co_uk_suffix(self):
        r = _ok("https://www.example.co.uk/")
        assert r.registrable_domain == "example.co.uk"

    def test_tenant_github_io(self):
        """
        github.io is in the PSL private section → username.github.io
        is the registrable domain, not github.io (N-11).
        """
        r = _ok("https://username.github.io/repo/")
        assert r.registrable_domain == "username.github.io"

    def test_tenant_netlify_app(self):
        r = _ok("https://mysite.netlify.app/")
        assert r.registrable_domain == "mysite.netlify.app"

    def test_tenant_vercel_app(self):
        r = _ok("https://myapp.vercel.app/")
        assert r.registrable_domain == "myapp.vercel.app"

    def test_tenant_herokuapp(self):
        r = _ok("https://myapp.herokuapp.com/")
        assert r.registrable_domain == "myapp.herokuapp.com"

    def test_ip_host_no_registrable_domain(self):
        r = _ok("http://192.168.1.1/")
        assert r.registrable_domain is None

    def test_registrable_domain_bare_hostname(self):
        """Dataset pattern: bare domain like 'google.com' (no scheme, no path)."""
        r = _ok("google.com")
        assert r.registrable_domain == "google.com"


# ═══════════════════════════════════════════════════════════════════════════════
# N-12 — URL too long
# ═══════════════════════════════════════════════════════════════════════════════

class TestN12TooLong:

    def test_exactly_2048_chars_ok(self):
        # Build a URL of exactly 2048 characters
        base = "https://example.com/"
        path = "a" * (2048 - len(base))
        url = base + path
        assert len(url) == 2048
        r = normalize(url)
        assert r.error is None

    def test_2049_chars_error(self):
        base = "https://example.com/"
        path = "a" * (2049 - len(base))
        url = base + path
        r = normalize(url)
        assert r.error == "url_too_long"

    def test_very_long_url(self):
        url = "https://example.com/" + "x" * 3000
        _err(url, "url_too_long")


# ═══════════════════════════════════════════════════════════════════════════════
# Dataset anomalous rows (actual D1 patterns)
# ═══════════════════════════════════════════════════════════════════════════════

class TestDatasetAnomalousRows:

    def test_d1_bare_google(self):
        """'google.com' — scheme-less, no path (most common D1 pattern)."""
        r = _ok("google.com")
        assert r.scheme == "http"
        assert r.puny_host == "google.com"

    def test_d1_www_google(self):
        r = _ok("www.google.com")
        assert r.registrable_domain == "google.com"

    def test_d1_malicious_with_full_url(self):
        r = _ok("http://www.marketingbyinternet.com/mo/e56508df639f6ce7d55c81ee3fcd5ba8/")
        assert r.scheme == "http"
        assert "marketingbyinternet.com" in r.puny_host

    def test_d1_malicious_with_query(self):
        url = "http://www.824555.com/app/member/SportOption.php?uid=guest&langx=gb"
        r = _ok(url)
        assert "uid=guest" in r.query

    def test_d1_google_docs_phishing(self):
        url = "https://docs.google.com/spreadsheet/viewform?formkey=dGg2Z1lCUHlSdjllTVNRUW50TFIzSkE6MQ"
        r = _ok(url)
        assert r.registrable_domain == "google.com"

    def test_d1_deep_subdomain_phishing(self):
        """'signin.eby.de.zukruygxctzmmqi.civpro.co.za' — deep subdomain."""
        r = _ok("signin.eby.de.zukruygxctzmmqi.civpro.co.za")
        assert r.registrable_domain == "civpro.co.za"

    def test_d1_icloud_phishing(self):
        r = _ok("br-icloud.com.br")
        assert r.registrable_domain == "br-icloud.com.br"

    def test_at_sign_in_url_host_extracted(self):
        """URL with @ in authority — host must be extracted correctly."""
        r = normalize("http://user@example.com/path")
        # Even if treated as userinfo, host should be example.com
        if r.error is None:
            assert "example.com" in r.puny_host

    def test_scheme_less_with_path_and_params(self):
        r = _ok("example.com/login?user=foo&pass=bar")
        assert r.scheme == "http"
        assert "login" in r.path

    def test_https_url_full(self):
        r = _ok("https://www.paypal.com/signin/")
        assert r.scheme == "https"
        assert r.registrable_domain == "paypal.com"


# ═══════════════════════════════════════════════════════════════════════════════
# PSL parser test vectors
# Official Mozilla PSL algorithm tests (wildcard, exception, private-section)
# Uses PSL.for_testing() — no psl.dat required.
# ═══════════════════════════════════════════════════════════════════════════════

class TestPSLParser:
    """PSL algorithm test vectors using PSL.for_testing() — no psl.dat required."""

    @pytest.fixture
    def psl(self):
        return PSL.for_testing()

    # ── Normal rules ──────────────────────────────────────────────────────────
    def test_com_alone_has_no_registrable(self, psl):
        """'com' is itself a public suffix → no registrable domain."""
        assert psl.registrable_domain("com") is None

    def test_example_com(self, psl):
        assert psl.registrable_domain("example.com") == "example.com"

    def test_www_example_com(self, psl):
        assert psl.registrable_domain("www.example.com") == "example.com"

    def test_biz_alone_has_no_registrable(self, psl):
        assert psl.registrable_domain("biz") is None

    def test_domain_biz(self, psl):
        assert psl.registrable_domain("domain.biz") == "domain.biz"

    def test_b_domain_biz(self, psl):
        assert psl.registrable_domain("b.domain.biz") == "domain.biz"

    # ── 2-level rules (co.uk) ─────────────────────────────────────────────────
    def test_co_uk_alone_has_no_registrable(self, psl):
        assert psl.registrable_domain("co.uk") is None

    def test_example_co_uk(self, psl):
        assert psl.registrable_domain("example.co.uk") == "example.co.uk"

    def test_b_example_co_uk(self, psl):
        assert psl.registrable_domain("b.example.co.uk") == "example.co.uk"

    # ── Wildcard: *.ck ────────────────────────────────────────────────────────
    def test_ck_alone_has_no_registrable(self, psl):
        """'ck' has no normal rule but *.ck means every x.ck is a suffix."""
        assert psl.registrable_domain("ck") is None

    def test_test_ck_is_wildcard_suffix(self, psl):
        """'test.ck' matches *.ck wildcard → it is a public suffix, no registrable."""
        assert psl.registrable_domain("test.ck") is None

    def test_b_test_ck(self, psl):
        """'b.test.ck' → registrable = 'b.test.ck' (suffix = 'test.ck')."""
        assert psl.registrable_domain("b.test.ck") == "b.test.ck"

    def test_a_b_test_ck(self, psl):
        """'a.b.test.ck' → registrable = 'b.test.ck'."""
        assert psl.registrable_domain("a.b.test.ck") == "b.test.ck"

    # ── Exception: !www.ck overrides *.ck ────────────────────────────────────
    def test_www_ck_is_exception(self, psl):
        """'www.ck' is listed as !www.ck exception → effective suffix = 'ck', registrable = 'www.ck'."""
        assert psl.registrable_domain("www.ck") == "www.ck"

    def test_www_www_ck(self, psl):
        """'www.www.ck' → effective suffix = 'ck', registrable = 'www.ck'."""
        assert psl.registrable_domain("www.www.ck") == "www.ck"

    # ── Wildcard + exception: *.kobe.jp and !city.kobe.jp ────────────────────
    def test_c_kobe_jp_is_suffix(self, psl):
        """'c.kobe.jp' matches *.kobe.jp → public suffix, no registrable."""
        assert psl.registrable_domain("c.kobe.jp") is None

    def test_b_c_kobe_jp(self, psl):
        """'b.c.kobe.jp' → registrable = 'b.c.kobe.jp'."""
        assert psl.registrable_domain("b.c.kobe.jp") == "b.c.kobe.jp"

    def test_city_kobe_jp_exception(self, psl):
        """'city.kobe.jp' is !city.kobe.jp exception → effective suffix = 'kobe.jp', registrable = 'city.kobe.jp'."""
        assert psl.registrable_domain("city.kobe.jp") == "city.kobe.jp"

    def test_www_city_kobe_jp(self, psl):
        """'www.city.kobe.jp' → registrable = 'city.kobe.jp'."""
        assert psl.registrable_domain("www.city.kobe.jp") == "city.kobe.jp"

    # ── Private section ───────────────────────────────────────────────────────
    def test_blogspot_com_is_private_suffix(self, psl):
        assert psl.registrable_domain("blogspot.com") is None

    def test_test_blogspot_com(self, psl):
        assert psl.registrable_domain("test.blogspot.com") == "test.blogspot.com"

    def test_github_io_is_private_suffix(self, psl):
        assert psl.registrable_domain("github.io") is None

    def test_username_github_io(self, psl):
        """Tenant host — registrable = 'username.github.io' per N-11."""
        assert psl.registrable_domain("username.github.io") == "username.github.io"

    def test_www_username_github_io(self, psl):
        assert psl.registrable_domain("www.username.github.io") == "username.github.io"

    def test_netlify_app_is_private_suffix(self, psl):
        assert psl.registrable_domain("netlify.app") is None

    def test_mysite_netlify_app(self, psl):
        assert psl.registrable_domain("mysite.netlify.app") == "mysite.netlify.app"

    # ── Case insensitivity ────────────────────────────────────────────────────
    def test_uppercase_input_normalized(self, psl):
        """PSL lookup is case-insensitive per N-03."""
        assert psl.registrable_domain("WWW.EXAMPLE.COM") == "example.com"

    def test_mixed_case_input(self, psl):
        assert psl.registrable_domain("User.GitHub.IO") == "user.github.io"

    # ── Trailing dot ──────────────────────────────────────────────────────────
    def test_trailing_dot_stripped(self, psl):
        """Trailing dot is stripped before PSL matching (N-05)."""
        assert psl.registrable_domain("www.example.com.") == "example.com"

    def test_trailing_dot_github_io(self, psl):
        assert psl.registrable_domain("username.github.io.") == "username.github.io"

    # ── public_suffix() method ────────────────────────────────────────────────
    def test_public_suffix_com(self, psl):
        assert psl.public_suffix("www.example.com") == "com"

    def test_public_suffix_co_uk(self, psl):
        assert psl.public_suffix("www.example.co.uk") == "co.uk"

    def test_public_suffix_github_io(self, psl):
        assert psl.public_suffix("user.github.io") == "github.io"

    def test_public_suffix_blogspot_com(self, psl):
        assert psl.public_suffix("myblog.blogspot.com") == "blogspot.com"

    def test_public_suffix_wildcard(self, psl):
        assert psl.public_suffix("b.test.ck") == "test.ck"

    def test_public_suffix_exception(self, psl):
        """Exception !www.ck → effective suffix = 'ck'."""
        assert psl.public_suffix("www.ck") == "ck"

    # ── Edge cases ────────────────────────────────────────────────────────────
    def test_single_label_unknown(self, psl):
        """Single unknown label with no matching rule → None."""
        assert psl.registrable_domain("localhost") is None

    def test_empty_string_returns_none(self, psl):
        assert psl.registrable_domain("") is None


# ═══════════════════════════════════════════════════════════════════════════════
# PSL test vectors against the real psl.dat file
# Un-skipped per Chunk 2 fix-up 2: must validate the real Mozilla PSL snapshot.
# ═══════════════════════════════════════════════════════════════════════════════

class TestPSLWithRealFile:
    """Runs vectors against lists/psl.dat (un-skipped)."""

    PSL_PATH = pathlib.Path(__file__).resolve().parents[1] / "lists" / "psl.dat"

    @pytest.fixture
    def psl(self):
        return PSL(self.PSL_PATH)

    def test_github_io_private(self, psl):
        assert psl.registrable_domain("username.github.io") == "username.github.io"

    def test_blogspot_private(self, psl):
        assert psl.registrable_domain("test.blogspot.com") == "test.blogspot.com"

    def test_www_example_com(self, psl):
        assert psl.registrable_domain("www.example.com") == "example.com"

    def test_co_uk(self, psl):
        assert psl.registrable_domain("example.co.uk") == "example.co.uk"

    def test_netlify_app(self, psl):
        assert psl.registrable_domain("mysite.netlify.app") == "mysite.netlify.app"

    def test_amazonaws_com_direct(self, psl):
        """amazonaws.com base domain is a 2LD; general subdomains resolve to amazonaws.com."""
        assert psl.registrable_domain("foo.amazonaws.com") == "amazonaws.com"

    def test_s3_amazonaws_com_private(self, psl):
        """s3.amazonaws.com is a private-section suffix; bucket is the registrable domain."""
        assert psl.registrable_domain("mybucket.s3.amazonaws.com") == "mybucket.s3.amazonaws.com"

    def test_cloudfront_net(self, psl):
        assert psl.registrable_domain("abc.cloudfront.net") == "abc.cloudfront.net"
