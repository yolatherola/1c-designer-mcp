"""Read-only compare against the exact newly observed DB configuration source."""
from pathlib import Path
import hashlib
import headless_comparison_carrier as previous

HERE=Path(__file__).resolve().parent
PINS={
 'headless_comparison_carrier.py':'2f10a11f592901b113bf45e9abcf1158b96019268faf5b53d55a5bfc4ea5ae68',
 'NativeHeadlessComparisonAdapter.c.inc':'a4f78e9bed8a88d55355005f21db075a8aa19c0784667544530ccbeeb024fc05',
 'NativePostUpdateComparison.c.inc':'2c8364ec33e973fe8ec3ee4af0c21a6754614f4fa4c2c8fe856c274ffd9e68e0',
}


def render():
    """Use the unchanged comparison core and code pins; no SDK/process calls."""
    parts={}
    for name,pin in PINS.items():
        raw=(HERE/name).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=pin:raise ValueError('POST_UPDATE_PIN '+name)
        parts[name]=raw.decode('utf-8').replace('\r','')
    source=previous.render().decode('utf-8')
    old=parts['NativeHeadlessComparisonAdapter.c.inc']
    if source.count(old)!=1:raise ValueError('POST_UPDATE_ADAPTER_ANCHOR')
    return source.replace(old,parts['NativePostUpdateComparison.c.inc'],1).encode('utf-8')
