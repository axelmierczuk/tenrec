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

To build native fixtures only (skipping Docker-based ones, useful when
the docker daemon isn't available):

```bash
python tenrec/tests/fixtures/build_fixtures.py --skip-docker
```

## Running the integration tests

```bash
export IDADIR="/path/to/ida"
uv run pytest tenrec/tests/integration -m fixture
```

## Adding a new native fixture target

1. Create `sources/<name>/CMakeLists.txt` and source files.
2. Register it in the top-level `CMakeLists.txt` with
   `add_subdirectory(sources/<name>)`.
3. Use `tenrec_apply_fixture_flags(<target>)` to inherit the standard
   debug/no-optimisation flags so IDA gets readable output.
4. Rebuild with `python build_fixtures.py`.
5. Add a corresponding `<name>_db` fixture in `tenrec/tests/conftest.py`
   and write integration tests under `tenrec/tests/integration/`.

## Adding a new Docker fixture target

Docker fixtures are how the live-debugger integration tests get a
reliable, headless target — gdbserver inside a container doesn't need
the entitlement gymnastics macOS does. The orchestrator looks for any
`sources/<name>/Dockerfile[.windows]` and treats it as a fixture target.

The Dockerfile suffix selects the target OS:

| Filename              | Target  | Where it builds          |
|-----------------------|---------|--------------------------|
| `Dockerfile`          | Linux   | any docker daemon        |
| `Dockerfile.windows`  | Windows | Windows-container daemon |

`build_fixtures.py` skips variants that don't match the local daemon's
`docker info --format '{{.OSType}}'` — Linux fixtures build on Linux
daemons, Windows fixtures build on Windows daemons. CI pipelines
typically run the build twice (once per platform) so both image flavors
are produced.

1. Create `sources/<name>/Dockerfile` (or `Dockerfile.windows`) plus any
   source files it COPYs.
2. The image must produce a binary at:
     * `/fixture/debugger` (Linux), or
     * `C:/fixture/debugger.exe` (Windows).
   `build_fixtures.py` extracts it via `docker cp` to feed `ida-domain`.
3. Set the default command to launch a gdb-remote server on port 31337,
   e.g. `CMD ["gdbserver", "0.0.0.0:31337", "/fixture/debugger"]` on
   Linux, or `CMD ["gdbserver.exe", "0.0.0.0:31337", "C:/fixture/debugger.exe"]`
   on Windows (MSYS2's gdb works for the Windows runtime).
4. Rebuild with `python build_fixtures.py`. The orchestrator builds the
   image (tagged `tenrec-fixture-<name>`) and copies the binary into
   `binaries/<name>` for IDA analysis.
5. Add a corresponding `<name>_db` fixture and a container manager
   fixture (see `gdbserver_container` / `gdbserver_windows_container`
   for the pattern) in `tenrec/tests/conftest.py`.

Each target should be focused: small, self-contained, and exercising one
clearly-defined slice of plugin behaviour. Prefer adding a new target over
piling more code into an existing one.
