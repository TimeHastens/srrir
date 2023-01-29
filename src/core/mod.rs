use sha256::try_digest;
use std::sync::mpsc::channel;
use std::{
    collections::HashMap,
    fs,
    io::{self, Write},
    path::Path,
    path::PathBuf,
};
use threadpool::ThreadPool;
use walkdir::WalkDir;

struct Samples {
    prepare_data: HashMap<PathBuf, String>,
    antivir_name: String,
    notes: String,
    sample_dir_path: String,
    fixed: i32,
    total_before: i32,
    total_now: i32,
}

pub fn core() {
    let pool = ThreadPool::new(num_cpus::get());
    let mut samples = Samples {
        prepare_data: HashMap::new(),
        antivir_name: String::new(),
        notes: String::new(),
        sample_dir_path: String::new(),
        fixed: 0,
        total_before: 0,
        total_now: 0,
    };
    println!("\nStart configuring...\n");
    print!("Dir path?    ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut samples.sample_dir_path).unwrap();
    samples.sample_dir_path = samples.sample_dir_path.trim().to_string();
    let sample_path = Path::new(&samples.sample_dir_path);
    let metadata = fs::metadata(sample_path).unwrap();
    if metadata.is_dir() == false {
        println!("Invalid path! It should be a Dir!");
    }
    print!("Anti-Virus name?    ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut samples.antivir_name).unwrap();
    samples.antivir_name = samples.antivir_name.trim().to_string();
    print!("Notes (Press Enter if it is empty)?    ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut samples.notes).unwrap();
    samples.notes = samples.notes.trim().to_string();
    if samples.notes.is_empty() == false {
        samples.notes = format!("Notes: {}\n", samples.notes);
    }
    println!("Configuration completed. Starting to prepare for it...");
    let pool2 = pool.clone();
    prepare_threads(&mut samples, pool);
    println!("\nPreparation completed. Now you can start to scan the samples with your Antivirus.\nIf the Antivirus finishes scanning, you can press \"ENTER\" to start the statistics.");
    let mut enterer = String::new();
    io::stdin().read_line(&mut enterer).unwrap();
    counter(&mut samples, pool2);
    println!("Statistics completed.\n");
    let bmn = samples.total_before - samples.total_now;
    let ttd = bmn + samples.fixed;
    let output_data = format!(
        "Antivirus name: {}\nSample size: {}\nTotal detections: {}\nThe total detections include:\n  -Deleted: {}\n  -Fixed: {}\nMissed: {}\nAccuracy: {:.4}%\n{}", 
        samples.antivir_name,
        samples.total_before, 
        ttd, 
        bmn, 
        samples.fixed, 
        samples.total_now, 
        100 * ttd / samples.total_before,
        samples.notes
    );
    println!("{}", output_data);
}

fn computes(paths: PathBuf) -> (PathBuf, String) {
    let path2 = paths.clone();
    (paths, try_digest(Path::new(&path2)).unwrap())
}

fn prepare_threads(samples: &mut Samples, pool: ThreadPool) {
    let (sendd, recc) = channel();
    for entry in WalkDir::new(&samples.sample_dir_path)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| !e.path().is_dir())
    {
        let this_sample = entry.path().to_owned();
        let sendd = sendd.clone();
        pool.execute(move || {
            sendd.send(computes(this_sample)).unwrap();
        });
    }
    drop(sendd);
    for this in recc.iter() {
        let (paths, sha256) = this;
        samples.prepare_data.insert(paths, sha256);
        samples.total_before += 1;
    }
}

fn counter(samples: &mut Samples, pool: ThreadPool) {
    let (sendd2, recc2) = channel();
    for entry in WalkDir::new(&samples.sample_dir_path)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| !e.path().is_dir())
    {
        let this_sample = entry.path().to_owned();
        let sendd2 = sendd2.clone();
        pool.execute(move || {
            sendd2.send(computes(this_sample)).unwrap();
        });
    }
    drop(sendd2);
    for this in recc2.iter() {
        samples.total_now += 1;
        println!("{}", samples.total_now);
        let (paths, sha256) = this;
        let sha_before = samples.prepare_data.get(&paths).unwrap();
        if sha_before != &sha256 {
            // fixed
            samples.fixed += 1;
        }
    }
}