use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use twizzler_async::FlagBlock;

struct ArpTableInner {
    entries: Mutex<BTreeMap<u32, u32>>,
    flag: FlagBlock,
}

struct ArpTable {
    inner: Arc<ArpTableInner>,
}

impl ArpTable {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ArpTableInner {
                entries: Mutex::new(BTreeMap::new()),
                flag: FlagBlock::new(),
            }),
        }
    }

    pub async fn lookup(&self, dst: u32) -> u32 {
        loop {
            let entries = self.inner.entries.lock().unwrap();
            if let Some(res) = entries.get(&dst) {
                return *res;
            }

            println!("didn't find arp entry");
            let fut = self.inner.flag.wait();
            println!("future created");
            drop(entries);
            println!("firing request");
            self.fire_arp_request(dst);
            println!("awaiting completion");
            fut.await;
        }
    }

    fn fire_arp_request(&self, dst: u32) {
        println!("fire arp request");
        let inner = self.inner.clone();
        std::thread::spawn(move || {
            println!("arp request sent...");
            std::thread::sleep(Duration::from_millis(1000));
            println!("inserting entry and signaling");
            inner.entries.lock().unwrap().insert(dst, 1234);
            inner.flag.signal_all();
        });
    }

    pub fn add_entry(&self, a: u32, b: u32) {
        self.inner.entries.lock().unwrap().insert(a, b);
        self.inner.flag.signal_all();
    }
}

pub fn test_arp() {
    let arp = ArpTable::new();
    twizzler_async::run(async {
        let ent = arp.lookup(1).await;
        println!("arp got: {}", ent);
    });
}