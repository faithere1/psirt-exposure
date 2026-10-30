# KEV fixture

`known_exploited_vulnerabilities.json` is a trimmed, hand-written sample in the schema of the CISA
KEV feed (<https://www.cisa.gov/known-exploited-vulnerabilities-catalog>). It exists only to test
the parser and the CLI offline. Dates and descriptions are illustrative; use the live feed
(`netsec-check check --kev cisa`) for real data.
