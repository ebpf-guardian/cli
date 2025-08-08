use criterion::{criterion_group, criterion_main, Criterion};

fn bench_cfg_build(c: &mut Criterion) {
    c.bench_function("cfg_build_simple", |b| {
        b.iter(|| {
            let path = std::path::Path::new("tests/data/simple.o");
            let rt = tokio::runtime::Runtime::new().unwrap();
            let _ = rt.block_on(async {
                let summary = ebpf_guardian::analyzer::analyze_bpf_program(path, None).await.unwrap();
                criterion::black_box(summary);
            });
        })
    });
}

criterion_group!(benches, bench_cfg_build);
criterion_main!(benches);

