import os
import re

in_file = r'D:\github\lorehub-all\lore\docs\testing-fork-delta-inventory.md'
out_file = in_file
app_file = r'D:\github\lorehub-all\lore\docs\testing-fork-delta-inventory-appendix.md'

with open(in_file, 'r', encoding='utf-8') as f:
    text = f.read()

bullets = re.split(r'\n- \*\*', text)

new_main = []
new_app = []

new_main.append('# Fork-delta inventory: `tideshift/main` vs upstream\n\n')
new_main.append('This is the per-module map from our fork\'s deltas to their most useful automated gates.\nFor detailed historical context, gotchas, and design invariants, see the [Appendix](testing-fork-delta-inventory-appendix.md).\n\n')

new_app.append('# Fork-delta inventory Appendix\n\nThis file contains detailed historical context and architectural invariants extracted from the main inventory.\n\n')

for b in bullets[1:]:
    b = '- **' + b
    if len(b) > 800:
        title_match = re.match(r'- \*\*([^*]+)\*\*', b)
        if title_match:
            title = title_match.group(1).replace('\n', ' ')
            
            gates = []
            for m in re.finditer(r'`(cargo test[^`]*)`', b):
                gates.append(f"`{m.group(1)}`")
            for m in re.finditer(r'`(pwsh -File [^`]*)`', b):
                gates.append(f"`{m.group(1)}`")
            for m in re.finditer(r'`(lore-[^`]*ps1)`', b):
                gates.append(f"`{m.group(1)}`")
            
            gates = list(dict.fromkeys(gates))
            
            anchor = re.sub(r'[^a-z0-9]+', '-', title.lower()).strip('-')
            gate_str = ' '.join(gates) if gates else 'See Appendix.'
            
            new_main.append(f'- **{title}**: See [Appendix](testing-fork-delta-inventory-appendix.md#{anchor}). Gates: {gate_str}\n')
            
            new_app.append(f'## {title}\n\n' + b.replace(f'- **{title_match.group(1)}**', '').lstrip(': ') + '\n\n')
        else:
            new_main.append(b + '\n')
    else:
        new_main.append(b + '\n')

with open(out_file, 'w', encoding='utf-8') as f:
    f.write(''.join(new_main))

with open(app_file, 'w', encoding='utf-8') as f:
    f.write(''.join(new_app))
print('Refactoring completed successfully.')
