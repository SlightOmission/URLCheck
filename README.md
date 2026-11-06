# URLCheck

Reads text (an abuse report, an email), pulls out every URL, checks each one against Google Safe Browsing, tests whether it still loads (PyFunceble), optionally submits it to urlscan.io, and prints a defanged report email for the site owner. Progress and warnings go to stderr, so stdout is only the email.

## Setup

```
uv tool install .            # puts `urlcheck` on your PATH
export GSB_API_KEY=...       # required
export URLSCAN_API_KEY=...   # optional
urlcheck -f report.txt > email.txt
urlcheck --help
```

Development: `uv sync`, then `make test` and `make lint`.

## Gotchas

- urlscan.io scans are submitted with `visibility: public`. Anything in the URLs (tokens, customer paths) becomes publicly searchable on urlscan.io.
- A URL whose status cannot be determined is treated as still live, so a flagged URL gets "Remove content" rather than "Request a review". Asking for removal of something already gone is cheaper than telling a customer to request a review while the content is still up.
