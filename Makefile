PY ?= python3

.PHONY: demo test cov serve smoke
demo:            ## regenerate the synthetic case, reports and dashboard data
	$(PY) -m forensictriage demo
test:
	$(PY) -m pytest
cov:
	$(PY) -m pytest --cov=forensictriage --cov-report=term-missing
serve:           ## dashboard at http://localhost:8000
	$(PY) -m http.server 8000 --directory dashboard
smoke:           ## needs: npm i playwright-core, and Chrome/Chromium
	node scripts/dashboard_smoke.js http://127.0.0.1:8000 screenshots
