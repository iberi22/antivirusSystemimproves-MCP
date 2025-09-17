from typing import Dict, List, Optional
from pathlib import Path


def _import_yara():
    try:
        import yara  # type: ignore
        return yara
    except Exception as e:
        return None


def compile_rules(*, rules_path: Optional[str] = None, rule_text: Optional[str] = None):
    yara = _import_yara()
    if yara is None:
        return None, {"error": "yara-python no instalado", "hint": "pip install yara-python"}
    try:
        if rule_text:
            return yara.compile(source=rule_text), None
        if rules_path:
            p = Path(rules_path)
            if p.is_dir():
                # compile all .yar/.yara in directory
                files = {str(pp): str(pp) for pp in p.rglob("*.yar")}
                files.update({str(pp): str(pp) for pp in p.rglob("*.yara")})
                if not files:
                    return None, {"error": "No se encontraron reglas en el directorio"}
                return yara.compile(filepaths=files), None
            else:
                return yara.compile(filepath=str(p)), None
        return None, {"error": "Debe proporcionar rules_path o rule_text"}
    except Exception as e:
        return None, {"error": str(e)}


def scan_path(target: str, *, rules_path: Optional[str] = None, rule_text: Optional[str] = None, recursive: bool = True, limit: int = 1000) -> Dict:
    yara = _import_yara()
    if yara is None:
        return {"error": "yara-python no instalado", "hint": "pip install yara-python"}
    rules, err = compile_rules(rules_path=rules_path, rule_text=rule_text)
    if err:
        return err
    base = Path(target).expanduser()
    files: List[Path] = []
    if base.is_file():
        files = [base]
    else:
        for p in base.rglob("*") if recursive else base.glob("*"):
            if p.is_file():
                files.append(p)
                if len(files) >= limit:
                    break
    matches: List[Dict] = []
    for f in files:
        try:
            m = rules.match(str(f))
            if m:
                for mm in m:
                    matches.append({
                        "path": str(f),
                        "rule": mm.rule,
                        "tags": mm.tags,
                        "meta": mm.meta,
                    })
        except Exception as e:
            matches.append({"path": str(f), "error": str(e)})
    return {"scanned": len(files), "matches": matches}


def test_rule(rule_text: str, sample_path: str) -> Dict:
    yara = _import_yara()
    if yara is None:
        return {"error": "yara-python no instalado", "hint": "pip install yara-python"}
    rules, err = compile_rules(rule_text=rule_text)
    if err:
        return err
    try:
        m = rules.match(str(Path(sample_path)))
        out = []
        for mm in m:
            out.append({"rule": mm.rule, "tags": mm.tags, "meta": mm.meta})
        return {"matches": out}
    except Exception as e:
        return {"error": str(e)}
