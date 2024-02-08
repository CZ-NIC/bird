use std::env;
use std::fs::File;
use serde_derive::Deserialize;

#[derive(Debug, Deserialize)]
struct Memory {
    effective: u32,
    overhead: u32,
}

#[derive(Debug, Deserialize)]
struct ShowMemoryBody {
    routing_tables: Memory,
    route_attributes: Memory,
    protocols: Memory,
    current_config: Memory,
    standby_memory: Memory,
    total: Memory,
}

#[derive(Debug, Deserialize)]
struct ShowMemory {
    header: String,
    body: ShowMemoryBody,
}

#[derive(Debug, Deserialize)]
struct ShowMemoryMessage {
    /* serde does not support prefix, so we use rename work-around */
    #[serde(rename(deserialize = "show_memory:message"))]
    message: ShowMemory,

    /* for prefixing both Serializator and Deserializator, use:
      #[serde(rename(serialize = "show_memory:message", deserialize = "show_memory:mesage"))]
     */
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
	println!("Usage: ./program {{show-memory-cbor-file}}");
	return;
    }

    let mut file = File::open(&args[1]);

    if file.is_err() {
	println!("Error during openning file {} occured!", args[1].clone());
	return;
    }

    let rep : Result<ShowMemoryMessage, _> = serde_cbor::from_reader(file.unwrap());
    if let Ok(report) = rep {
	println!("{:?}", report);
    } else {
	let err = rep.err().unwrap();
	println!("Error {}", err);
    }
}
