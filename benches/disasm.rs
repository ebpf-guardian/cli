use criterion::{criterion_group, criterion_main, Criterion};

fn bench_disasm(c: &mut Criterion) {
    c.bench_function("disassemble_simple", |b| {
        b.iter(|| {
            let path = std::path::Path::new("tests/data/simple.o");
            let _ins = ebpf_guardian::analyzer::disassembler::disassemble(path).unwrap();
        })
    });
}

criterion_group!(benches, bench_disasm);
criterion_main!(benches);

