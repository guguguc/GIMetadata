use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct Section {
    pub name: String,
    pub va: u64,
    pub raw_off: usize,
    pub raw_size: usize,
}

#[derive(Clone)]
pub struct Pe {
    pub data: Vec<u8>,
    pub image_base: u64,
    pub sections: Vec<Section>,
}

impl Pe {
    pub fn open(path: &Path) -> Result<Self> {
        let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        anyhow::ensure!(data.len() >= 0x40, "truncated PE");
        let pe = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
        anyhow::ensure!(data.get(pe..pe + 4) == Some(b"PE\0\0"), "not PE");
        let nsec = u16::from_le_bytes(data[pe + 6..pe + 8].try_into().unwrap()) as usize;
        let opt = u16::from_le_bytes(data[pe + 0x14..pe + 0x16].try_into().unwrap()) as usize;
        let so = pe + 0x18 + opt;
        let image_base = u64::from_le_bytes(data[pe + 0x18 + 0x18..pe + 0x18 + 0x20].try_into().unwrap());
        let mut sections = Vec::new();
        for i in 0..nsec {
            let e = so + i * 40;
            let name = String::from_utf8_lossy(&data[e..e + 8])
                .trim_end_matches('\0').to_string();
            let vsz = u32::from_le_bytes(data[e + 8..e + 12].try_into().unwrap()) as usize;
            let vaddr = u32::from_le_bytes(data[e + 12..e + 16].try_into().unwrap()) as u64;
            let rsz = u32::from_le_bytes(data[e + 16..e + 20].try_into().unwrap()) as usize;
            let roff = u32::from_le_bytes(data[e + 20..e + 24].try_into().unwrap()) as usize;
            sections.push(Section { name, va: image_base + vaddr, raw_off: roff, raw_size: rsz.min(vsz) });
        }
        Ok(Self { data, image_base, sections })
    }

    pub fn va2off(&self, va: u64) -> Option<usize> {
        for s in &self.sections {
            if va >= s.va && va < s.va + s.raw_size as u64 {
                return Some(s.raw_off + (va - s.va) as usize);
            }
        }
        None
    }
}
