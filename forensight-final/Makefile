PYTHON ?= python3

venv:
	$(PYTHON) -m venv .venv

install:
	. .venv/bin/activate && pip install -r requirements.txt

tools:
	. .venv/bin/activate && PYTHONPATH=. python -m app.cli tools

route:
	. .venv/bin/activate && PYTHONPATH=. python -m app.cli route $(INPUT) $(KIND)

process:
	. .venv/bin/activate && PYTHONPATH=. python -m app.cli process $(INPUT) --output $(OUT) $(KIND)

demo:
	. .venv/bin/activate && PYTHONPATH=. python -m app.cli process sample_data/synthetic_forensic_events.json --output output/demo

test:
	. .venv/bin/activate && PYTHONPATH=. pytest -q

api:
	. .venv/bin/activate && uvicorn app.main:app --reload
