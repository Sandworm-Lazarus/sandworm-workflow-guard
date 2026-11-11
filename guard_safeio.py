"""Bounded local input/process helpers. Original Sandworm code, MIT."""
import json
import os
import selectors
import signal
import subprocess
import time
from pathlib import Path

MAX_JSON = 4 * 1024 * 1024

class InputError(ValueError):
    """Only fixed, non-sensitive messages may be used."""

def read_bytes(path, limit=MAX_JSON):
    try:
        p = Path(path)
        if p.is_symlink() or not p.is_file():
            raise InputError("INPUT_FILE_REQUIRED")
        with p.open("rb") as f:
            data = f.read(limit + 1)
        if len(data) > limit:
            raise InputError("INPUT_TOO_LARGE")
        return data
    except OSError:
        raise InputError("INPUT_UNREADABLE") from None

def parse_json(data):
    if len(data) > MAX_JSON:
        raise InputError("INPUT_TOO_LARGE")
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise InputError("DUPLICATE_JSON_KEY")
            out[key] = value
        return out
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(InputError("INVALID_JSON_NUMBER")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, InputError):
            raise
        raise InputError("INVALID_JSON") from None

def bounded_run(argv, cwd, timeout=60, limit=MAX_JSON):
    """Linux worker runner: no shell, inherited tokens/config, or stderr text."""
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(cwd),
           "NO_COLOR": "1", "GOMAXPROCS": "2", "ZIZMOR_OFFLINE": "1"}
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
    except OSError:
        raise InputError("ENGINE_UNAVAILABLE") from None
    output = bytearray()
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise InputError("ENGINE_TIMEOUT")
            for key, _ in selector.select(min(.1, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output.extend(chunk)
                if len(output) > limit:
                    raise InputError("ENGINE_OUTPUT_TOO_LARGE")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise InputError("ENGINE_TIMEOUT")
        try:
            status = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise InputError("ENGINE_TIMEOUT") from None
        if status != 0:
            raise InputError("ENGINE_FAILED")
        return bytes(output)
    finally:
        selector.close()
        process.stdout.close()
        # Descendants may retain inherited stdout even after the parent exits.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()

def write_json(path, value):
    text = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    try:
        with open(path, "x", encoding="utf-8") as f:
            f.write(text)
    except FileExistsError:
        raise InputError("OUTPUT_EXISTS") from None
    except OSError:
        raise InputError("OUTPUT_UNWRITABLE") from None
