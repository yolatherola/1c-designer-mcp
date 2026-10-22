"""Hash the static local Python import closure without importing target code.

Only direct modules in the explicitly supplied directories are supported.
Dynamic imports are outside this contract. Ambiguous names, local packages,
relative imports and changing files fail rather than silently omit a source.
"""
import ast
import hashlib
from pathlib import Path
import stat

LIMIT = 1024 * 1024


def _checked(path, directory=False):
    path = Path(path).absolute()
    try:
        resolved = path.resolve(strict=True)
        info = path.lstat()
    except OSError as error:
        raise ValueError('V124_SOURCE_UNAVAILABLE') from error
    if resolved != path or stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise ValueError('V124_SOURCE_REDIRECTED')
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ValueError('V124_SOURCE_KIND')
    return path


def _read(path):
    _checked(path)
    raw = path.read_bytes()
    if not 0 < len(raw) <= LIMIT:
        raise ValueError('V124_SOURCE_SIZE')
    return raw


def _local_import(name, roots):
    base = name.split('.')[0]
    matches = [root / (base + '.py') for root in roots if (root / (base + '.py')).exists()]
    # Namespace packages have no __init__.py. Both kinds need a package-aware
    # resolver, so this direct-module contract refuses either kind explicitly.
    if any((root / base).is_dir() for root in roots):
        raise ValueError('V124_LOCAL_PACKAGE_UNSUPPORTED')
    if len(matches) > 1:
        raise ValueError('V124_AMBIGUOUS_LOCAL_IMPORT')
    if not matches:
        return None
    if '.' in name:
        raise ValueError('V124_LOCAL_SUBMODULE_UNSUPPORTED')
    return _checked(matches[0])


def local_python_source_hashes(seeds, module_roots):
    """Return Path -> SHA256 for seeds and their static local imports.

    Parameters are existing Python files and explicit module search directories.
    This reads source text only, runs no target module, and writes nothing.
    A final reread rejects changes made during dependency discovery.
    """
    roots = tuple(sorted({_checked(root, directory=True) for root in module_roots}))
    if not roots:
        raise ValueError('V124_SOURCE_ROOTS')
    pending = {_checked(seed) for seed in seeds}
    if not pending:
        raise ValueError('V124_SOURCE_SEEDS')
    if any(path.suffix != '.py' or path.parent not in roots for path in pending):
        raise ValueError('V124_SOURCE_BOUNDARY')
    hashes = {}
    resolutions = {}
    while pending:
        path = min(pending)
        pending.remove(path)
        if path in hashes:
            continue
        raw = _read(path)
        try:
            tree = ast.parse(raw.decode('utf-8-sig'), filename=str(path))
        except (UnicodeError, SyntaxError) as error:
            raise ValueError('V124_SOURCE_PARSE') from error
        hashes[path] = hashlib.sha256(raw).hexdigest()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [item.name for item in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    raise ValueError('V124_RELATIVE_IMPORT_UNSUPPORTED')
                names = [node.module] if node.module else []
            else:
                continue
            for name in names:
                candidate = _local_import(name, roots)
                if name in resolutions and resolutions[name] != candidate:
                    raise ValueError('V124_IMPORT_RESOLUTION_CHANGED')
                resolutions[name] = candidate
                if candidate is not None and candidate not in hashes:
                    pending.add(candidate)
    for path, digest in hashes.items():
        if hashlib.sha256(_read(path)).hexdigest() != digest:
            raise ValueError('V124_SOURCE_CHANGED_DURING_SCAN')
    for root in roots:
        _checked(root, directory=True)
    # Hashes alone miss a new local module or a new duplicate in another root.
    # Repeat resolution even for imports which previously had no local file.
    for name, candidate in resolutions.items():
        if _local_import(name, roots) != candidate:
            raise ValueError('V124_IMPORT_RESOLUTION_CHANGED')
    return dict(sorted(hashes.items()))
