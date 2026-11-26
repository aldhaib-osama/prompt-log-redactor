# prompt-log-redactor

Redact common secret and personal patterns from model interaction logs before the logs are shared or archived.

You give it a log JSON (a string, or nested objects/lists of strings). It returns the redacted document plus per-category counts. Patterns covered: emails, API-key-shaped tokens, bearer tokens, JWTs, international phone numbers, and AWS access key IDs.

## What it is

- An offline, pattern-based redactor for learning log hygiene.
- Deterministic: same input, same output, so you can diff the result.

## What it is NOT

- Not a DLP product. It catches the shapes it knows and misses the rest.
- Not proof a log is safe to share. Always spot-check the output.
- It does not detect meaning-level leaks (a secret spelled out in words).

## Usage

```
python prompt_log_redactor.py example.json
```

`example.json` is fictional and contains fake secrets so you can see the masks.

## Tests

```
python -m unittest -v
```

[VERIFY: run the tests yourself before citing the count in an interview.]

## Provenance

Initial code was AI-assisted. [TO FILL: Dahoba's own review notes.]
