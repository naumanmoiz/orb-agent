"""The guard's slugify must equal django.utils.text.slugify, not approximate it.

The plugin's transformer slugs every reference that carries none, using
Django's slugify, and AutoSlugMatcher then matches on that slug alone -- no
name, no group. A slug computed differently here is a slug the agent will
never match, so the object is created a second time and the preflight reports
it as fine.

Every expectation below was produced by running the real
django.utils.text.slugify on NetBox 4.6, not by reading its source. Regenerate
with:

    from django.utils.text import slugify
    [(n, slugify(n)) for n in NAMES]
"""
import pytest

from bootstrap_custom_fields import slugify

# (name, what django.utils.text.slugify actually returns)
DJANGO_SLUGS = [
    # plain names -- where the old hand-rolled version agreed
    ("Corp", "corp"),
    ("Lab-A", "lab-a"),
    ("Corp Ltd", "corp-ltd"),
    ("Corp & Co", "corp-co"),
    ("ACME  Inc.", "acme-inc"),
    ("Corp--Ltd", "corp-ltd"),
    # underscores survive: \w includes _
    ("Lab_A", "lab_a"),
    # punctuation is DELETED, not turned into a separator
    ("Corp.Ltd", "corpltd"),
    ("R&D", "rd"),
    ("a/b/c", "abc"),
    ("10.1 Net", "101-net"),
    ("AT&T Corp.", "att-corp"),
    ("50% Ltd", "50-ltd"),
    ("tenant(old)", "tenantold"),
    ("EMEA/APAC", "emeaapac"),
    ("site #1", "site-1"),
    # accents fold to ASCII rather than being dropped
    ("Café", "cafe"),
    ("Münich", "munich"),
    ("Zürich-Nord", "zurich-nord"),
    ("naïve café", "naive-cafe"),
    ("Ünïcode Tenant", "unicode-tenant"),
    # both ends strip hyphen AND underscore
    ("_leading", "leading"),
    ("trailing_", "trailing"),
    ("-dash-", "dash"),
    # degenerate input must not raise
    ("", ""),
    ("   ", ""),
    ("___", ""),
    ("...", ""),
    ("Ø", ""),
]


@pytest.mark.parametrize("name,expected", DJANGO_SLUGS)
def test_matches_django_slugify(name, expected):
    """Exact equality with Django, including the cases the old version missed."""
    assert slugify(name) == expected


def test_regressions_the_old_implementation_introduced():
    """These five are why a near-enough slugify created duplicate objects.

    The old version replaced each run of non-alphanumerics with a hyphen, so
    it produced a slug NetBox would never generate, and check_roles then
    looked up a role that could not exist.
    """
    assert slugify("Corp.Ltd") != "corp-ltd"
    assert slugify("Lab_A") != "lab-a"
    assert slugify("R&D") != "r-d"
    assert slugify("Café") != "caf"
    assert slugify("10.1 Net") != "10-1-net"
