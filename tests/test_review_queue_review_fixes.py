import json
import unittest
from pathlib import Path

import review_queue


class ReviewQueueReviewFixTests(unittest.TestCase):
    def test_inline_code_keeps_underscores_readable(self):
        self.assertEqual(review_queue._code("baseline_not_found"), "`baseline_not_found`")

    def test_inline_code_uses_longer_fence_for_embedded_backtick(self):
        self.assertEqual(review_queue._code("value`with_tick"), "`` value`with_tick ``")

    def test_committed_queue_renders_code_values_without_literal_escape_backslashes(self):
        queue = json.loads(Path("security-review/queue.json").read_text(encoding="utf-8"))
        markdown = review_queue.render_markdown(queue)
        self.assertIn("`baseline_not_found`", markdown)
        self.assertNotIn("`baseline\\_not\\_found`", markdown)


if __name__ == "__main__":
    unittest.main()
