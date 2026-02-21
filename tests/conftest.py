# BEATRIX Test Configuration

# Exclude live_integration.py from pytest collection —
# it makes real HTTP calls and is meant to be run standalone.
collect_ignore = ["live_integration.py"]
