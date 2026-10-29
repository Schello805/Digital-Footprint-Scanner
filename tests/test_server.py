from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_static_files():
    # Test index page
    res_index = client.get("/")
    assert res_index.status_code == 200
    assert "/static/css/tailwind.min.css" in res_index.text
    assert "/static/css/custom.css" in res_index.text
    print("✓ Index page served successfully with local CSS references.")

    # Test local CSS files
    res_tw = client.get("/static/css/tailwind.min.css")
    assert res_tw.status_code == 200
    assert len(res_tw.content) > 100000
    print(f"✓ tailwind.min.css served ({len(res_tw.content)} bytes)")

    res_custom = client.get("/static/css/custom.css")
    assert res_custom.status_code == 200
    assert "bg-slate-950" in res_custom.text
    print("✓ custom.css served")

    res_leaflet_css = client.get("/static/css/leaflet.css")
    assert res_leaflet_css.status_code == 200
    print("✓ leaflet.css served")

    # Test local JS files
    res_leaflet_js = client.get("/static/js/leaflet.js")
    assert res_leaflet_js.status_code == 200
    print("✓ leaflet.js served")

    res_app_js = client.get("/static/js/app.js")
    assert res_app_js.status_code == 200
    print("✓ app.js served")

if __name__ == "__main__":
    test_static_files()
    print("🎉 All static assets verified successfully!")
