use criterion::{criterion_group, criterion_main, Criterion};
// use codecrafters_dns_server::fibonacci;

pub fn criterion_benchmark(c: &mut Criterion) {
    //     c.bench_function("fib 20", |b| b.iter(|| fibonacci(black_box(20))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
