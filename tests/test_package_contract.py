import json
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PackageContractTests(unittest.TestCase):
    def test_all_published_package_versions_match(self):
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
        versions = [
            pyproject["project"]["version"],
            json.loads((ROOT / "package.json").read_text())["version"],
            json.loads((ROOT / "frontend/package.json").read_text())["version"],
            json.loads((ROOT / "goodmorning.module.json").read_text())["version"],
        ]
        self.assertEqual(versions, ["0.1.5"] * 4)


if __name__ == "__main__":
    unittest.main()
