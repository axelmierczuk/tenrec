# Test fixtures

Compiled C binaries and their analysed IDA databases, used by the
integration tests under `tenrec/tests/integration/`.

The unit tests under `tenrec/tests/unit/` use mocks and run without these
fixtures. Integration tests (`@pytest.mark.fixture`) skip automatically if
no built database is present.

## Layout

```
fixtures/
├── CMakeLists.txt          # Top-level build config; one add_subdirectory() per target
├── build_fixtures.py       # Orchestrator: cmake build + ida-domain analysis
├── sources/<target>/       # One subdir per fixture: CMakeLists.txt + sources
├── build/                  # CMake build tree                (gitignored)
├── binaries/               # Compiled executables            (gitignored)
└── databases/              # Analysed .i64 databases         (gitignored)
```

## Building

```bash
export IDADIR="/path/to/ida"   # e.g. /Applications/IDA Professional 9.2.app/Contents/MacOS
python tenrec/tests/fixtures/build_fixtures.py
```

The script is idempotent — re-running rebuilds incrementally and replaces
existing databases. To wipe everything:

```bash
python tenrec/tests/fixtures/build_fixtures.py --clean
```

To build binaries without producing IDA databases (useful for contributors
without an IDA license):

```bash
python tenrec/tests/fixtures/build_fixtures.py --skip-database
```

## Running the integration tests

```bash
export IDADIR="/path/to/ida"
uv run pytest tenrec/tests/integration -m fixture
```

## Adding a new fixture target

1. Create `sources/<name>/CMakeLists.txt` and source files.
2. Register it in the top-level `CMakeLists.txt` with
   `add_subdirectory(sources/<name>)`.
3. Use `tenrec_apply_fixture_flags(<target>)` to inherit the standard
   debug/no-optimisation flags so IDA gets readable output.
4. Rebuild with `python build_fixtures.py`.
5. Add a corresponding `<name>_database_path` / `<name>_handler` pair in
   `tenrec/tests/conftest.py` and write integration tests under
   `tenrec/tests/integration/`.

Each target should be focused: small, self-contained, and exercising one
clearly-defined slice of plugin behaviour. Prefer adding a new target over
piling more code into an existing one.
