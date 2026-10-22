"""Fidelity and build-contract checks for the user-selected web panel."""
import json
import re
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]


class PanelAssetsTests(unittest.TestCase):
    def test_original_nettinx_values_are_preserved_in_both_modes(self):
        base=ROOT/'panel/web/src/experience'
        original=json.loads((base/'sources/nettinx.json').read_text(encoding='utf-8'))
        css=(base/'styles/nettinx/tokens.css').read_text(encoding='utf-8')
        blocks=re.findall(r'\[data-style="nettinx"\](?:\[data-mode="dark"\])?\s*\{([^}]+)\}',css)
        self.assertEqual(len(blocks),2)
        for mode,block in zip(['light','dark'],blocks):
            actual=dict(re.findall(r'--([\w-]+):\s*([^;]+);',block))
            for key,value in original['styles'][mode].items():
                self.assertEqual(actual.get(key),value,f'{mode}/{key}')
        self.assertFalse((base/'styles/nettinx/adjustments.css').exists(),'original palette must not get unapproved corrections')

    def test_embedded_runtime_has_no_external_frontend_dependencies(self):
        html=(ROOT/'panel/web/index.html').read_text(encoding='utf-8')
        self.assertNotIn('https://',html)
        config=(ROOT/'panel/web/vite.config.ts').read_text(encoding='utf-8')
        self.assertIn('../internal/ui/dist',config)
        module=(ROOT/'panel/go.mod').read_text(encoding='utf-8')
        self.assertIn('golang.org/x/crypto',module)

    def test_release_versions_match(self):
        version=re.search(r'^GTM_VERSION=(\d+\.\d+\.\d+)$',(ROOT/'src/core.sh').read_text(encoding='utf-8'),re.M)[1]
        self.assertIn('PANEL_VERSION='+version,(ROOT/'panel-install.sh').read_text(encoding='utf-8'))
        self.assertIn('const Version = "'+version+'"',(ROOT/'panel/cmd/gtm-panel/main.go').read_text(encoding='utf-8'))
