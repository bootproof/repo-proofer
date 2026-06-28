# Publishing repo-proofer to PyPI

This guide covers the one-time setup and per-release steps to publish
repo-proofer to PyPI so that `uvx repo-proofer <url>` and
`pipx install repo-proofer` work for everyone.

## Prerequisites (one-time)

1. **Create a PyPI account** at https://pypi.org/account/register/
2. **Enable 2FA** (required for PyPI)
3. **Create an API token** at https://pypi.org/manage/account/token/
   - Scope: "Entire account" (or scope to the `repo-proofer` project after first publish)
   - Copy the token — it starts with `pypi-` and you won't see it again

## Per-release steps

### 1. Verify the package builds

```bash
cd /path/to/repo-proofer
python3 -m build
```

This produces:
- `dist/repo_proofer-<version>-py3-none-any.whl` (the wheel — what gets installed)
- `dist/repo_proofer-<version>.tar.gz` (the sdist — source distribution)

Verify the wheel contains the entry point:
```bash
unzip -p dist/repo_proofer-*.whl "*/entry_points.txt"
# Should show:
# [console_scripts]
# repo-proofer = proofer:cli
```

### 2. Publish to PyPI

**Option A: Using `uv` (recommended)**
```bash
uv publish dist/*
```
When prompted, enter your PyPI username as `__token__` and your API token
as the password.

**Option B: Using `twine`**
```bash
pip install twine
twine upload dist/*
```
When prompted:
- Username: `__token__`
- Password: your full API token (starts with `pypi-`)

### 3. Verify the publish

```bash
# Should return the package metadata, not 404
pip index versions repo-proofer

# Or test directly:
uvx repo-proofer --help
pipx run repo-proofer --help
```

### 4. Test the one-command install

```bash
# From a clean environment (no local clone):
uvx repo-proofer https://github.com/pallets/markupsafe.git
```

This should work for anyone on earth with `uv` installed.

## Version bumping

1. Update `__version__` in `proofer.py`
2. Update `version` in `pyproject.toml` (must match)
3. Commit: `git commit -am "bump: v0.2.1"`
4. Tag: `git tag v0.2.1 && git push origin v0.2.1`
5. Build + publish (steps above)
6. Clean old dist: `rm dist/*` before rebuilding

## CI auto-publish (optional, after first manual publish)

Add to `.github/workflows/release.yml`:

```yaml
name: Release
on:
  push:
    tags: ['v*']
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: '3.11'}
      - run: pip install build twine
      - run: python -m build
      - run: twine upload dist/*
        env:
          TWINE_USERNAME: __token__
          TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
```

Then every `git tag v0.x.y && git push origin v0.x.y` auto-publishes.
