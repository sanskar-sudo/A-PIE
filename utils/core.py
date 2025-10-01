import os
import tempfile
from datetime import datetime
from typing import Dict, Optional

import bs4
import pefile
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed


def check_api(api_name: str, verbose: bool = False, session: Optional[requests.Session] = None) -> Optional[Dict[str, str]]:
    """Query malapi.io for a given WinAPI symbol.

    Returns a mapping of {api_name: description} if found; otherwise None.
    """
    if verbose:
        print(f"[*] {api_name}")

    sess = session or requests.Session()
    response = sess.get(f"https://malapi.io/winapi/{api_name}")
    response.raise_for_status()
    soup = bs4.BeautifulSoup(response.text, "html.parser")
    details = soup.select(".detail-container .content")
    if not details or len(details) < 2:
        return None
    api_info = details[1].get_text().strip()
    if not api_info:
        return None
    if verbose:
        print(f"[!] Hit: {api_name}")
    return {api_name: api_info}


def _collect_import_names(pe: pefile.PE, verbose: bool = False) -> Dict[str, None]:
    """Build a unique set of API names to query, including A/W counterparts."""
    unique: Dict[str, None] = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imp in entry.imports:
            try:
                if not hasattr(imp, "name") or imp.name is None:
                    continue
                imp_name = imp.name.decode("utf-8").strip()
                if not imp_name:
                    continue
                unique[imp_name] = None
                if imp_name.endswith("W"):
                    unique[f"{imp_name[:-1]}A"] = None
                elif imp_name.endswith("A"):
                    unique[f"{imp_name[:-1]}W"] = None
            except Exception:
                continue
    return unique


def fetch_api_descriptions(api_names, verbose: bool = False, max_workers: int = 12, on_progress=None) -> Dict[str, str]:
    """Fetch MalAPI descriptions in parallel using a shared session.

    - api_names: iterable of strings
    - on_progress: optional callback(name, hit: Optional[str], error: Optional[str])
    """
    results: Dict[str, str] = {}
    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_to_name = {
                pool.submit(check_api, name, verbose, session): name for name in api_names
            }
            for future in as_completed(future_to_name):
                name = future_to_name[future]
                try:
                    res = future.result()
                    if res:
                        results.update(res)
                        if on_progress:
                            on_progress(name, res.get(name), None)
                    else:
                        if on_progress and verbose:
                            on_progress(name, None, None)
                except Exception as e:
                    if on_progress:
                        on_progress(name, None, str(e))
    return results


def analyze_pe(pe_path: str, verbose: bool = False) -> Dict[str, str]:
    """Analyze a PE's import table and return suspicious WinAPI descriptions.

    Returns mapping {api_name: description}.
    """
    results: Dict[str, str] = {}
    pe = pefile.PE(pe_path, fast_load=True)
    pe.parse_data_directories()

    unique = _collect_import_names(pe, verbose=verbose)
    results = fetch_api_descriptions(unique.keys(), verbose=verbose)
    return results


def analyze_uploaded_pe_bytes(data: bytes, verbose: bool = False) -> Dict[str, str]:
    """Analyze uploaded PE bytes without permanently writing to disk."""
    fd, tmp_path = tempfile.mkstemp(prefix="malapi_", suffix=".bin")
    os.close(fd)
    try:
        with open(tmp_path, "wb") as f:
            f.write(data)
        return analyze_pe(tmp_path, verbose=verbose)
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass


def stream_analyze_uploaded_pe_bytes(data: bytes, verbose: bool = True):
    """Generator that yields log lines as analysis progresses (for SSE/streaming)."""
    fd, tmp_path = tempfile.mkstemp(prefix="malapi_", suffix=".bin")
    os.close(fd)
    try:
        with open(tmp_path, "wb") as f:
            f.write(data)
        pe = pefile.PE(tmp_path, fast_load=True)
        pe.parse_data_directories()
        unique = _collect_import_names(pe, verbose=verbose)
        total = len(unique)
        yielded = 0
        yield f"event: meta\ndata: total={total}\n\n"

        def on_progress(name: str, hit: Optional[str], error: Optional[str]):
            nonlocal yielded
            yielded += 1
            if error:
                yield_line = f"event: log\ndata: {yielded}/{total} {name} ERROR: {error}\n\n"
            elif hit:
                yield_line = f"event: hit\ndata: {name}\\n--> {hit}\n\n"
            else:
                # Only log misses when verbose
                yield_line = f"event: log\ndata: {yielded}/{total} {name} miss\n\n" if verbose else ""
            if yield_line:
                yield yield_line

        # Run parallel fetch with streaming callbacks
        results: Dict[str, str] = {}
        with requests.Session() as session:
            with ThreadPoolExecutor(max_workers=12) as pool:
                future_to_name = {
                    pool.submit(check_api, name, verbose, session): name for name in unique.keys()
                }
                for future in as_completed(future_to_name):
                    name = future_to_name[future]
                    try:
                        res = future.result()
                        if res:
                            results.update(res)
                            yield f"event: hit\ndata: {name}\\n--> {res.get(name)}\n\n"
                        else:
                            if verbose:
                                yield f"event: log\ndata: {name} miss\n\n"
                    except Exception as e:
                        yield f"event: log\ndata: {name} ERROR: {str(e)}\n\n"

        # Final results payload
        yield "event: done\n" + "data: END\n\n"
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass


def write_report(results: Dict[str, str], sample_name: Optional[str] = None) -> str:
    """Write results to a timestamped log file in reports/ and return its path."""
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M")
    filename = f"reports/{timestamp}_report.log"
    with open(filename, "a", encoding="utf-8") as log:
        if sample_name:
            log.write(f"Sample: {sample_name}\n")
        for api_name, desc in results.items():
            log.write(f"{api_name}\n    \\---> {desc}\n")
        log.write("\n\nIf a WINAPI listed here was used maliciously, but no description was given, consider contributing information to https://malapi.io.\n Thank you for using MalAPIReader!\n sanskarr\n")
    return filename


