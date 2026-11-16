import re
from bs4 import BeautifulSoup


class MetadataAnalyzer:
    """Website Metadata and OpenGraph Inspector."""

    @classmethod
    def extract_metadata(cls, html_content: str, fallback_url: str = "") -> dict:
        """Extract title, description, generator, canonical URL, lang, and OpenGraph tags."""
        result = {
            "title": None,
            "description": None,
            "generator": None,
            "canonical_url": None,
            "language": None,
            "open_graph": {},
        }

        if not html_content:
            return result

        try:
            soup = BeautifulSoup(html_content[:500000], "html.parser")
        except Exception:
            return result

        # 1. Page Title
        if soup.title and soup.title.string:
            result["title"] = soup.title.string.strip()

        # 2. HTML Language tag
        html_tag = soup.find("html")
        if html_tag and html_tag.get("lang"):
            result["language"] = html_tag["lang"].strip()

        # 3. Canonical Link
        canonical = soup.find("link", rel=lambda val: val and "canonical" in val.lower())
        if canonical and canonical.get("href"):
            result["canonical_url"] = canonical["href"].strip()

        # 4. Meta Description & Generator
        for meta in soup.find_all("meta"):
            name = (meta.get("name") or "").lower().strip()
            prop = (meta.get("property") or "").lower().strip()
            content = (meta.get("content") or "").strip()

            if name == "description" and not result["description"]:
                result["description"] = content
            elif name == "generator" and not result["generator"]:
                result["generator"] = content

            # OpenGraph properties (og:*)
            if prop.startswith("og:") and content:
                key = prop[3:]  # strip 'og:'
                result["open_graph"][key] = content

        return result
