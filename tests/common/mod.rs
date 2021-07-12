use std::path::PathBuf;

pub fn get_tests_root() -> PathBuf {
    let mut p = PathBuf::new();
    p.push(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");

    p
}

pub fn get_out_root() -> PathBuf {
    let mut p = get_tests_root().to_path_buf();
    p.push("out");

    p
}

pub fn get_client_config_path() -> PathBuf {
    let mut p = get_tests_root().to_path_buf();
    p.push("config");
    p.push("client.toml");

    p
}

pub fn get_receiver_config_path() -> PathBuf {
    let mut p = get_tests_root().to_path_buf();
    p.push("config");
    p.push("server.toml");

    p
}
