import csv
from pathlib import Path
from ml.build_external import build_e1


def test_e1_requires_minimum_and_never_publishes_partial(tmp_path):
    inp=tmp_path/'e1.csv'
    with inp.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=['URL']); w.writeheader()
        w.writerow({'URL':'https://example.com/about'})
    try:
        build_e1(inp,tmp_path,minimum_urls=2,minimum_domains=2)
    except ValueError as e:
        assert 'insufficient' in str(e).lower()
    else:
        assert False, 'Expected insufficient E1 to fail closed'
    assert not (tmp_path/'data'/'external'/'E1_training.csv').exists()
