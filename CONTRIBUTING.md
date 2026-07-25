# Contributing to SpoofScore

Thanks for your interest in contributing. Here's how you can help.

## Reporting bugs

Open an issue with:
- The domain you scanned (if you can share it)
- The full error output
- Your Python version (`python --version`)
- Your OS

## Suggesting features

Open an issue describing what you want and why it matters.

## Pull requests

1. Fork the repo
2. Create a branch (`git checkout -b feature/your-idea`)
3. Make your changes
4. Test on a few domains to make sure nothing breaks
5. Submit a PR with a clear description

## Code style

- Keep it simple. No unnecessary dependencies
- Every network call should be wrapped in try/except
- Follow the existing naming patterns
- Test your changes against at least 3 real domains before submitting

## Adding DKIM selectors

If you know of DKIM selectors used by a mail provider not currently covered, add them to the `DKIM_SELECTORS` list or `PROVIDER_DKIM_SELECTORS` dict and submit a PR. This is one of the easiest ways to improve the tool.

## Adding RBL zones

To add a new DNSBL zone, add it to the `RBL_ZONES` list. Make sure the zone is publicly queryable and not rate limited too aggressively.

## Questions

Use GitHub Discussions for questions, ideas, or showing your scan results.
