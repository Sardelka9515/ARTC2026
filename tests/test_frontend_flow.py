import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FrontendFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (ROOT / "frontend/templates/index.html").read_text()
        cls.js = (ROOT / "frontend/static/js/flow.js").read_text()

    def test_user_can_select_all_three_interfaces(self):
        for element_id in ("cfg-iface", "attack-iface", "wids-iface", "pineapple-iface"):
            self.assertIn(f'id="{element_id}"', self.html)
        self.assertIn('/api/pineapple/interfaces', self.js)

    def test_item_mapping_matches_platform_requirements(self):
        self.assertIn('testId: 5, label: "防 Rogue AP / 釣魚熱點', self.js)
        self.assertIn('testId: 8, selectionOnly: true, label: "無線入侵偵測 WIDS/WIPS', self.js)
        self.assertIn('testId: 9, label: "偵測大量重傳 / 非法握手', self.js)

    def test_panel_rows_only_show_original_name_and_status(self):
        self.assertNotIn("item-detail", self.js)
        self.assertEqual(self.js.count('testId: 28, label:'), 1)

    def test_item_28_starts_wids_before_deauth_and_checks_both_alerts(self):
        attack = self.js[self.js.index("async function runAttackSim()"):
                         self.js.index("//  PIPELINE DRIVER")]
        self.assertLess(attack.index("runWids()"), attack.index('runScenarioJob("deauth"'))
        self.assertIn('event.type === "deauth_flood"', attack)
        self.assertIn('"tsf_collision"', attack)

    def test_evil_twin_uses_selected_network_ssid(self):
        self.assertIn('params.ssid = (ctx.networks || []).find(', self.js)


if __name__ == "__main__":
    unittest.main()
