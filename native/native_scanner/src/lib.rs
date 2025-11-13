use pyo3::prelude::*;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use walkdir::WalkDir;

fn hash_file(path: &str) -> PyResult<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

#[pyfunction]
fn scan_path_parallel(path: String) -> PyResult<Vec<String>> {
    let walker = WalkDir::new(path).into_iter();

    let hashes: Vec<String> = walker
        .filter_map(|e| e.ok())
        .par_bridge()
        .filter_map(|entry| {
            if entry.file_type().is_file() {
                if let Ok(hash) = hash_file(entry.path().to_str().unwrap()) {
                    Some(hash)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    Ok(hashes)
}

#[pymodule]
fn native_scanner(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan_path_parallel, m)?)?;
    Ok(())
}
