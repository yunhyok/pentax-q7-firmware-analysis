"""Build the FC1 control-bit provenance and HDR task lifecycle report (hdr-task-report.html)."""
from build_deep_report import ROOT, read, esc
from verify_routing import witnesses


def hexlist(values):
    return ', '.join(f'{x:#x}' for x in values)


def main():
    v = {}
    sem = read('fc1-semantics.json')
    create = read('task-create-followup.json')
    done = read('task-completion-followup.json')
    classes = read('hdr-pass-followup.json')['fresh_hdr']['pass_classes']

    # FC1 control bit: topology input type classification.
    v['class_rows'] = ''.join(
        f'<tr><th scope="row" class="n">{c["T"]}</th><td><code>{esc(c["condition"])}</code></td>'
        f'<td>{hexlist(c["input_formats"]) if "input_formats" in c else "그 밖의 값"}</td></tr>'
        for c in sem['topology_type']['ordered_classification'])
    v['mapped_rows'] = ''.join(
        f'<tr><th scope="row">{esc(m["descriptor_type_name"])}</th><td class="n">{m["descriptor_type"]}</td>'
        f'<td><code>{m["input_format"]:#x}</code></td><td class="n">{m["topology_input_type"]}</td></tr>'
        for m in sem['topology_type']['mapped_examples'])
    v['direct_rows'] = ''.join(
        f'<tr><th scope="row">ID <code>{d["id"]}</code> · version {", ".join(d["versions"])}</th>'
        f'<td><code>{esc(d["value"])}</code></td><td>{", ".join(f"<code>{s}</code>" for s in d["setters"])}</td></tr>'
        for d in sem['descriptor_sources'])
    v['related_rows'] = ''.join(
        f'<tr><th scope="row">{b["block"]}</th><td class="n">{b["mode"]}</td><td><code>+{b["packed_payload_offset"]}</code></td>'
        f'<td><code>{b["mmio"]}</code></td><td><code>{b["setter"]}</code> / <code>{b["writer"]}</code></td></tr>'
        for b in sem['control_word']['related_blocks'])
    r = sem['replay']
    writers = r['descriptor_writer_cases']
    v['writer_case_count'] = str(len(writers))
    v['writer_write_total'] = str(sum(len(c['ordered_mmio_writes']) for c in writers))
    v['semantics_case_count'] = str(len(r['topology_format_cases']) + len(r['descriptor_mapping_cases']) + len(writers))
    v['format_case_count'] = str(len(r['topology_format_cases']))
    v['mapping_case_count'] = str(len(r['descriptor_mapping_cases']))
    v['writer_rows'] = ''.join(
        f'<tr><th scope="row">ID <code>{c["descriptor_id"]:#x}</code> · v<code>{c["version"]:#x}</code></th>'
        f'<td><code>{c["source_control_word"]:#010x}</code></td><td><code>{c["emitted_control_word"]:#010x}</code></td>'
        f'<td class="n">{len(c["ordered_mmio_writes"])}</td></tr>' for c in writers)

    # Task creation replay.
    t = create['replay']['result']
    v['task_rows'] = ''.join(
        f'<tr><th scope="row">{i} / {esc(classes[i])}</th><td class="n">{t["task_ids"][i]}</td>'
        f'<td class="n">{t["final_flags"][i]}</td><td class="n">{t["task_fields"][i]["0x224"]}</td>'
        f'<td class="n">{fc["uid"]}</td><td class="n">{fc["enabled"]}</td><td class="n">{fc["flags"]}</td></tr>'
        for i, fc in enumerate(t['fc1']))
    v['queue_ids'] = '→'.join(str(x) for x in t['queue_task_ids'])
    v['uids'] = '·'.join(str(fc['uid']) for fc in t['fc1'])
    v['enabled'] = '·'.join(str(fc['enabled']) for fc in t['fc1'])
    v['flags'] = '·'.join(str(fc['flags']) for fc in t['fc1'])
    v['task_count'] = str(len(t['task_ids']))
    v['task_vtable'] = t['task_vtables'][0]
    v['create_stub_count'] = str(len(create['replay']['stubs']))
    v['create_stubs'] = ''.join(
        f'<tr><th scope="row"><code>{pc}</code></th><td>{esc(name)}</td></tr>'
        for pc, name in create['replay']['stubs'].items())

    # Completion replay.
    d = done['replay']
    v['irq_rows'] = ''.join(
        f'<tr><td class="n">{c["end"]}</td><td class="n">{c["counter"]}</td><td class="n">{c["next_counter"]}</td>'
        f'<td>{"예" if 0x815ccc74 in c["flags"] else "아니요"}</td></tr>' for c in d['irq_cases'])
    v['callback_rows'] = ''.join(
        f'<tr><th scope="row">{c["pass_index"]}</th><td class="n">{c["completed_passes"]}</td>'
        f'<td>{", ".join(f"<code>{x:#010x}</code>" for x in c["flags"]) or "없음"}</td>'
        f'<td>{"예" if c["path_done"] else "아니요"}</td></tr>' for c in d['callback_cases'])
    groups = [('IRQ 조건', 'irq_cases'), ('큐 전송', 'queue_cases'), ('드라이버 대기', 'worker_cases'),
              ('네 패스 콜백', 'callback_cases'), ('하위 이미지', 'subimage_cases')]
    v['completion_breakdown'] = ', '.join(f'{name} {len(d[key])}' for name, key in groups)
    v['completion_case_count'] = str(sum(len(d[key]) for _, key in groups))
    v['done_models'] = ''.join(
        f'<tr><th scope="row"><code>{pc}</code></th><td>{esc(name)}</td></tr>'
        for pc, name in d['modeled_functions'].items())
    v['timeout_ticks'] = f"{d['worker_cases'][0]['timeout_ticks']:,}"

    docs = [sem, create, done]
    v['function_count'] = str(len({f['address'] for x in docs for f in x['selected_functions']}))
    v['word_count'] = f"{sum(len(list(witnesses(x))) for x in docs):,}"
    k3 = read('task-comparison.json')
    v['k3_commit'] = k3['latest_public_main_sha_verified_via_gh']
    v['k3_base'] = k3['k3_public_repository'] + '/blob/' + v['k3_commit'] + '/analysis/'

    page = (ROOT / 'analysis/task-template.html').read_text(encoding='utf-8')
    for key, value in v.items():
        page = page.replace('{{' + key + '}}', value)
    assert '{{' not in page
    (ROOT / 'hdr-task-report.html').write_text(page, encoding='utf-8', newline='\n')
    print('Built hdr-task-report.html')


if __name__ == '__main__':
    main()
