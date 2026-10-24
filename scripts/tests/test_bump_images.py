import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("bump", Path(__file__).resolve().parents[1] / "bump-images.py")
bump = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bump)

TAGS = ["1.99.0-trixie", "1.99.1-trixie", "1.100.0-trixie", "1.100.0-bookworm", "2.0.0-trixie", "1.100.0-rc1-trixie", "latest"]


class BumpImages(unittest.TestCase):
    def test_split_ref(self):
        self.assertEqual(bump.split_ref("postgres:9.9-alpine"), ("registry-1.docker.io", "library/postgres", "9.9-alpine"))
        self.assertEqual(bump.split_ref("grafana/grafana:1.2.3"), ("registry-1.docker.io", "grafana/grafana", "1.2.3"))
        self.assertEqual(bump.split_ref("ghcr.io/dexidp/dex:v1.2.3"), ("ghcr.io", "dexidp/dex", "v1.2.3"))
        self.assertIsNone(bump.split_ref("nsmithuk/local-kms@sha256:" + "0" * 64))

    def test_same_stream_only(self):
        # same suffix, same first number: bumped; a new first number is only reported
        self.assertEqual(bump.newest("1.99.0-trixie", TAGS), ("1.100.0-trixie", "2.0.0-trixie"))

    def test_single_number_tag_is_all_major(self):
        self.assertEqual(bump.newest("18-alpine", ["17-alpine", "18-alpine", "19-alpine", "19"]), (None, "19-alpine"))

    def test_k3s_suffix_numbers_compare(self):
        tags = ["v1.35.4-k3s1", "v1.35.4-k3s2", "v1.35.5-k3s1", "v1.36.0-k3s1"]
        self.assertEqual(bump.newest("v1.35.4-k3s1", tags), ("v1.36.0-k3s1", None))

    def test_moving_tag_has_no_shape(self):
        self.assertIsNone(bump.tag_shape("nonroot"))

    def test_parse_env_ignores_other_lines(self):
        env = "# c\nPOSTGRES_IMAGE=postgres:9.9-alpine\nGRAFANA_TRINO_PLUGIN=trino-datasource@1.2.0\n"
        self.assertEqual(bump.parse_env(env), {"POSTGRES_IMAGE": "postgres:9.9-alpine"})


if __name__ == "__main__":
    unittest.main()
