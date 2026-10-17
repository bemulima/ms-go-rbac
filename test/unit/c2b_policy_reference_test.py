import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/check-agent-policy.sh"

class ExactBundleExclusion(unittest.TestCase):
    def fixture(self, root):
        script = SCRIPT.read_text()
        for name in re.search(r'required_files="([^"]+)"', script)[1].split():
            file = root / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text("")
        (root / "README.md").write_text("")
        bundle = root / ".ai/testing/policy/policy-runner.cjs"
        bundle.parent.mkdir(parents=True, exist_ok=True)
        bundle.write_text("negative test string: prompts/legacy")
        return script

    def test_only_exact_generated_bundle_is_excluded(self):
        for probe in [None, "AGENTS.md", "docs/README.md", ".ai/rules/probe.md", ".ai/other/policy-runner.cjs"]:
            with self.subTest(probe=probe), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                script = self.fixture(root)
                if probe:
                    file = root / probe
                    file.parent.mkdir(parents=True, exist_ok=True)
                    file.write_text("obsolete reference: prompts/legacy")
                result = subprocess.run(["sh", "-c", script], cwd=root, capture_output=True, text=True)
                self.assertEqual(result.returncode, 1 if probe else 0, result.stderr)
                if probe:
                    self.assertIn("obsolete external knowledge reference found", result.stderr)

if __name__ == "__main__":
    unittest.main()
