Terminal agent behavior drift and capability expansion monitor.

Run tests:
python -m unittest discover -s tests -v

Compile production code:
python -m compileall -q driftwatch

Run offline acceptance:
python -m driftwatch.acceptance --fixture fixtures/acceptance.json --output output/acceptance

Run the CLI directly:
python -m driftwatch --db output/demo.sqlite ingest fixtures/acceptance.json --strict
python -m driftwatch --db output/demo.sqlite report output/report.json
