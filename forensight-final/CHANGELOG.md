# Changelog

## v5.1
- Fixed clean-checkout pytest imports by adding `pytest.ini` with `pythonpath = .`.
- Verified Plaso normalization: invalid timestamps become `null`, valid timestamps become ISO 8601 UTC, and placeholder fields become `null`.
- Verified 17-field normalized event contract remains unchanged.
