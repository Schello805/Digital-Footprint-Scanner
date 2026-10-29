import unittest
from fastapi.testclient import TestClient
from app.main import app
from app.modules.unsubscribe_hub import generate_unsubscribe_package, generate_batch_broker_optout_package, MARKETING_LIST_BROKERS

class TestUnsubscribeHub(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_generate_unsubscribe_package_rfc_and_gdpr(self):
        pkg = generate_unsubscribe_package(
            list_identifier="dev-discuss@python-list.org",
            user_email="john.doe@example.com",
            user_name="John Doe",
            lang="en"
        )
        self.assertTrue(pkg["success"])
        data = pkg["data"]
        
        # Verify RFC 2369 / Mailman daemon command
        self.assertEqual(data["mailman_request_email"], "dev-discuss-request@python-list.org")
        self.assertIn("dev-discuss-request@python-list.org", data["rfc_mailto"])
        self.assertIn("subject=unsubscribe", data["rfc_mailto"])
        self.assertEqual(data["web_options_url"], "https://python-list.org/mailman/options/dev-discuss")

        # Verify GDPR Art. 21 & Art. 17 objection text
        self.assertIn("Article 21(2)", data["gdpr_body"])
        self.assertIn("john.doe@example.com", data["gdpr_body"])
        self.assertIn("John Doe", data["gdpr_body"])

    def test_generate_unsubscribe_package_de_localization(self):
        pkg = generate_unsubscribe_package(
            list_identifier="newsletter@marketing-versand.de",
            user_email="max.mustermann@web.de",
            user_name="Max Mustermann",
            lang="de"
        )
        self.assertTrue(pkg["success"])
        data = pkg["data"]
        self.assertIn("Widerspruch gem. Art. 21", data["gdpr_subject"])
        self.assertIn("Art. 21 Abs. 2 DSGVO", data["gdpr_body"])
        self.assertIn("Art. 17 DSGVO", data["gdpr_body"])
        self.assertIn("Max Mustermann", data["gdpr_body"])
        self.assertIn("detected_category_de", data)
        self.assertIn("legal_summary_de", data)
        self.assertIn("protocol_summary_de", data)

    def test_api_unsubscribe_generate_endpoint(self):
        response = self.client.post("/api/unsubscribe/generate", json={
            "list_identifier": "security-alerts@infosec.org",
            "user_email": "auditor@pentest.com",
            "user_name": "Audit Lead",
            "lang": "en"
        })
        self.assertEqual(response.status_code, 200)
        res_json = response.json()
        self.assertTrue(res_json["success"])
        self.assertEqual(res_json["data"]["mailman_request_email"], "security-alerts-request@infosec.org")

    def test_api_brokers_endpoint(self):
        response = self.client.get("/api/unsubscribe/brokers")
        self.assertEqual(response.status_code, 200)
        res_json = response.json()
        self.assertTrue(res_json["success"])
        brokers = res_json["brokers"]
        self.assertGreaterEqual(len(brokers), 6)
        broker_names = [b["name"] for b in brokers]
        self.assertTrue(any("Schober" in name for name in broker_names))
        self.assertTrue(any("Acxiom" in name for name in broker_names))

    def test_generate_batch_broker_optout_package(self):
        pkg = generate_batch_broker_optout_package(
            user_email="victim@privacy.org",
            user_name="Target Person",
            user_phone="+49170111222",
            user_city="Berlin",
            lang="de"
        )
        self.assertTrue(pkg["success"])
        data = pkg["data"]
        self.assertGreaterEqual(data["brokers_count"], 7)
        self.assertIn("bcc=", data["batch_mailto"])
        self.assertIn("victim@privacy.org", data["body"])
        self.assertIn("Target Person", data["body"])
        self.assertIn("+49170111222", data["body"])
        self.assertIn("Berlin", data["body"])

    def test_api_batch_brokers_endpoint(self):
        response = self.client.post("/api/unsubscribe/batch-brokers", json={
            "user_email": "test.user@company.de",
            "user_name": "Test User",
            "lang": "en"
        })
        self.assertEqual(response.status_code, 200)
        res_json = response.json()
        self.assertTrue(res_json["success"])
        self.assertIn("batch_mailto", res_json["data"])
        self.assertIn("test.user@company.de", res_json["data"]["body"])

    def test_api_recon_mailinglists_endpoint(self):
        response = self.client.get("/api/recon/mailinglists?email=test.user@python.org")
        self.assertEqual(response.status_code, 200)
        res_json = response.json()
        self.assertTrue(res_json["success"])
        self.assertIn("found_lists", res_json["data"])
        self.assertIn("found_count", res_json["data"])
        self.assertIn("has_valid_mx", res_json["data"])
        self.assertEqual(res_json["data"]["email"], "test.user@python.org")

if __name__ == "__main__":
    unittest.main()
