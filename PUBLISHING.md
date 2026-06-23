# Publishing `renfield-mcp` to PyPI

The package builds clean and `twine check` passes. These are the **final manual
steps** — they need your PyPI credentials, so run them yourself.

## 0. Prerequisites (once)
- A PyPI account: <https://pypi.org/account/register/>
- An API token: PyPI → Account settings → API tokens → "Add API token"
  (scope it to the `renfield-mcp` project after the first upload; before that use
  an account-wide token).
- Tooling: `pip install build twine`

## 1. Build a clean distribution
```bash
rm -rf dist build src/*.egg-info
python -m build              # -> dist/renfield_mcp-X.Y.Z.tar.gz + .whl
twine check dist/*           # must say PASSED for both
```

## 2. Smoke-test the wheel in a throwaway venv
```bash
python3 -m venv /tmp/renf-test
/tmp/renf-test/bin/pip install dist/renfield_mcp-*.whl
cd /tmp && /tmp/renf-test/bin/ren quickstart   # must run end-to-end (lab is bundled)
```

## 3. Upload to TestPyPI first (recommended)
```bash
twine upload --repository testpypi dist/*
# verify the listing renders, then install from TestPyPI:
pip install --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ renfield-mcp
```

## 4. Upload to real PyPI
```bash
twine upload dist/*
# username: __token__
# password: <your pypi-... API token>
```
Then confirm:
```bash
pip install renfield-mcp
ren quickstart
```

## 5. After the first release
- Scope the API token to the `renfield-mcp` project.
- Consider a GitHub Actions release workflow with PyPI **Trusted Publishing**
  (OIDC, no stored token) triggered on a `v*` tag.

## Notes
- Distribution name is `renfield-mcp`; the import package and CLI stay `renfield` / `ren`.
- The bundled vulnerable lab ships at `renfield/lab/vuln_server.py` so `ren quickstart`
  works for pip users (kept byte-identical to `examples/vuln_server.py` by a test).
- A version can never be re-uploaded to PyPI — bump `version` in `pyproject.toml`
  and `src/renfield/__init__.py` for every release.
