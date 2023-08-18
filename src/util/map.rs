#![allow(dead_code)]
#![allow(unused_mut)]
use std::{
    collections::{btree_map, BTreeMap, HashMap, HashSet},
    hash::Hash,
    io::BufRead,
    mem::replace,
    path::Path,
};

use anyhow::{anyhow, bail, ensure, Error, Result};
use cwdemangle::{demangle, DemangleOptions};
use multimap::MultiMap;
use once_cell::sync::Lazy;
use regex::{Captures, Regex};

use crate::{
    obj::{
        section_kind_for_section, ObjInfo, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags,
        ObjSymbolKind,
    },
    util::file::{map_file, map_reader},
};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SymbolKind {
    Function,
    Object,
    Section,
    NoType,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SymbolVisibility {
    Unknown,
    Global,
    Local,
    Weak,
}

#[derive(Debug, Clone)]
pub struct SymbolEntry {
    pub name: String,
    pub demangled: Option<String>,
    pub kind: SymbolKind,
    pub visibility: SymbolVisibility,
    pub unit: Option<String>,
    pub address: u32,
    pub size: u32,
    pub align: Option<u32>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SymbolRef {
    pub name: String,
    pub unit: Option<String>,
}

#[derive(Default)]
struct SectionOrder {
    symbol_order: Vec<SymbolRef>,
    unit_order: Vec<(String, Vec<String>)>,
}

#[inline]
fn is_code_section(section: &str) -> bool { matches!(section, ".text" | ".init") }

/// Iterate over the BTreeMap and generate an ordered list of symbols and TUs by address.
fn resolve_section_order(
    _address_to_symbol: &BTreeMap<u32, SymbolRef>,
    symbol_entries: &mut HashMap<SymbolRef, SymbolEntry>,
) -> Result<SectionOrder> {
    let ordering = SectionOrder::default();

    // let mut last_unit = String::new();
    // let mut last_section = String::new();
    // let mut section_unit_idx = 0usize;
    // for symbol_ref in address_to_symbol.values() {
    //     if let Some(symbol) = symbol_entries.get_mut(symbol_ref) {
    //         if last_unit != symbol.unit {
    //             if last_section != symbol.section {
    //                 ordering.unit_order.push((symbol.section.clone(), vec![]));
    //                 section_unit_idx = ordering.unit_order.len() - 1;
    //                 last_section = symbol.section.clone();
    //             }
    //             let unit_order = &mut ordering.unit_order[section_unit_idx];
    //             if unit_order.1.contains(&symbol.unit) {
    //                 // With -common on, .bss is split into two parts. The TU order repeats
    //                 // at the end with all globally-deduplicated BSS symbols. Once we detect
    //                 // a duplicate inside of .bss, we create a new section and start again.
    //                 // TODO the first entry in .comm *could* be a TU without regular .bss
    //                 if symbol.section == ".bss" {
    //                     log::debug!(".comm section detected, duplicate {}", symbol.unit);
    //                     ordering.unit_order.push((".comm".to_string(), vec![symbol.unit.clone()]));
    //                     section_unit_idx = ordering.unit_order.len() - 1;
    //                 } else {
    //                     bail!(
    //                         "TU order conflict: {} exists multiple times in {}.",
    //                         symbol.unit, symbol.section,
    //                     );
    //                 }
    //             } else {
    //                 unit_order.1.push(symbol.unit.clone());
    //             }
    //             last_unit = symbol.unit.clone();
    //         }
    //         // For ASM-generated objects, notype,local symbols in .text
    //         // are usually local jump labels, and should be ignored.
    //         if is_code_section(&symbol.section)
    //             && symbol.size == 0
    //             && symbol.kind == SymbolKind::NoType
    //             && symbol.visibility == SymbolVisibility::Local
    //         {
    //             // Being named something other than lbl_* could indicate
    //             // that it's actually a local function, but let's just
    //             // make the user resolve that if necessary.
    //             if !symbol.name.starts_with("lbl_") {
    //                 log::warn!("Skipping local text symbol {}", symbol.name);
    //             }
    //             continue;
    //         }
    //         // Guess the symbol type if necessary.
    //         if symbol.kind == SymbolKind::NoType {
    //             if is_code_section(&symbol.section) {
    //                 symbol.kind = SymbolKind::Function;
    //             } else {
    //                 symbol.kind = SymbolKind::Object;
    //             }
    //         }
    //         ordering.symbol_order.push(symbol_ref.clone());
    //     } else {
    //         bail!("Symbol has address but no entry: {symbol_ref:?}");
    //     }
    // }

    for iter in ordering.symbol_order.windows(2) {
        let next_address = symbol_entries.get(&iter[1]).unwrap().address;
        let symbol = symbol_entries.get_mut(&iter[0]).unwrap();
        // For ASM-generated objects, we need to guess the symbol size.
        if symbol.size == 0 {
            symbol.size = next_address - symbol.address;
        }
    }

    Ok(ordering)
}

macro_rules! static_regex {
    ($name:ident, $str:expr) => {
        static $name: Lazy<Regex> = Lazy::new(|| Regex::new($str).unwrap());
    };
}

// Link map
static_regex!(LINK_MAP_START, "^Link map of (?P<entry>.*)$");
static_regex!(
    LINK_MAP_ENTRY,
    "^\\s*(?P<depth>\\d+)] (?P<sym>.*) \\((?P<type>.*),(?P<vis>.*)\\) found in (?P<tu>.*)$"
);
static_regex!(
    LINK_MAP_ENTRY_GENERATED,
    "^\\s*(?P<depth>\\d+)] (?P<sym>.*) found as linker generated symbol$"
);
static_regex!(
    LINK_MAP_ENTRY_DUPLICATE,
    "^\\s*(?P<depth>\\d+)] >>> UNREFERENCED DUPLICATE (?P<sym>.*)$"
);
static_regex!(LINK_MAP_EXTERN_SYMBOL, "^\\s*>>> SYMBOL NOT FOUND: (.*)$");

// Section layout
static_regex!(SECTION_LAYOUT_START, "^(?P<section>.*) section layout$");
static_regex!(
    SECTION_LAYOUT_SYMBOL,
    "^\\s*(?P<rom_addr>[0-9A-Fa-f]+|UNUSED)\\s+(?P<size>[0-9A-Fa-f]+)\\s+(?P<addr>[0-9A-Fa-f]{8}|\\.{8})\\s+(?P<offset>[0-9A-Fa-f]{8}|\\.{8})\\s+(?P<align>\\d+)?\\s*(?P<sym>.*?)(?:\\s+\\(entry of (?P<entry_of>.*?)\\))?\\s+(?P<tu>.*)$"
);
static_regex!(
    SECTION_LAYOUT_HEADER,
    "^(\\s*Starting\\s+Virtual\\s*(File\\s*)?|\\s*address\\s+Size\\s+address\\s*(offset\\s*)?|\\s*-----------------------(----------)?\\s*)$"
);

// Memory map
static_regex!(MEMORY_MAP_START, "^\\s*Memory map:\\s*$");
static_regex!(MEMORY_MAP_HEADER, "^(\\s*Starting Size\\s+File\\s*|\\s*address\\s+Offset\\s*)$");
static_regex!(MEMORY_MAP_ENTRY, "^\\s*(?P<section>\\S+)\\s+(?P<addr>[0-9A-Fa-f]+|\\.{0,8})\\s+(?P<size>[0-9A-Fa-f]+|\\.{1,8})\\s+(?P<offset>[0-9A-Fa-f]+|\\.{1,8})\\s*$");

// Linker generated symbols
static_regex!(LINKER_SYMBOLS_START, "^\\s*Linker generated symbols:\\s*$");
static_regex!(LINKER_SYMBOL_ENTRY, "^\\s*(?P<name>\\S+)\\s+(?P<addr>[0-9A-Fa-f]+|\\.{0,8})\\s*$");

pub struct SectionInfo {
    name: String,
    address: u32,
    size: u32,
    file_offset: u32,
}

#[derive(Default)]
pub struct MapInfo {
    pub entry_point: String,
    pub unit_entries: MultiMap<String, SymbolRef>,
    pub entry_references: MultiMap<SymbolRef, SymbolRef>,
    pub entry_referenced_from: MultiMap<SymbolRef, SymbolRef>,
    // pub address_to_symbol: BTreeMap<u32, SymbolRef>,
    // pub unit_section_ranges: HashMap<String, HashMap<String, Range<u32>>>,
    // pub symbol_order: Vec<SymbolRef>,
    // pub unit_order: Vec<(String, Vec<String>)>,
    pub sections: BTreeMap<u32, SectionInfo>,
    pub link_map_symbols: HashMap<SymbolRef, SymbolEntry>,
    pub section_symbols: HashMap<String, BTreeMap<u32, Vec<SymbolEntry>>>,
    pub section_units: HashMap<String, Vec<(u32, String)>>,
}

#[derive(Default)]
struct LinkMapState {
    last_symbol_name: String,
    symbol_stack: Vec<SymbolRef>,
}

#[derive(Default)]
struct SectionLayoutState {
    current_section: String,
    current_unit: Option<String>,
    units: Vec<(u32, String)>,
    symbols: BTreeMap<u32, Vec<SymbolEntry>>,
    has_link_map: bool,
}

enum ProcessMapState {
    None,
    LinkMap(LinkMapState),
    SectionLayout(SectionLayoutState),
    MemoryMap,
    LinkerGeneratedSymbols,
}

struct StateMachine {
    state: ProcessMapState,
    result: MapInfo,
    has_link_map: bool,
}

impl StateMachine {
    fn process_line(&mut self, line: String) -> Result<()> {
        if line.trim().is_empty() {
            return Ok(());
        }
        match &mut self.state {
            ProcessMapState::None => {
                if let Some(captures) = LINK_MAP_START.captures(&line) {
                    self.result.entry_point = captures["entry"].to_string();
                    self.switch_state(ProcessMapState::LinkMap(Default::default()))?;
                } else if let Some(captures) = SECTION_LAYOUT_START.captures(&line) {
                    self.switch_state(ProcessMapState::SectionLayout(SectionLayoutState {
                        current_section: captures["section"].to_string(),
                        has_link_map: self.has_link_map,
                        ..Default::default()
                    }))?;
                } else if MEMORY_MAP_START.is_match(&line) {
                    self.switch_state(ProcessMapState::MemoryMap)?;
                } else if LINKER_SYMBOLS_START.is_match(&line) {
                    self.switch_state(ProcessMapState::LinkerGeneratedSymbols)?;
                } else {
                    bail!("Unexpected line while processing map: '{line}'");
                }
            }
            ProcessMapState::LinkMap(ref mut state) => {
                if let Some(captures) = LINK_MAP_ENTRY.captures(&line) {
                    StateMachine::process_link_map_entry(captures, state, &mut self.result)?;
                } else if let Some(captures) = LINK_MAP_ENTRY_GENERATED.captures(&line) {
                    StateMachine::process_link_map_generated(captures, state, &mut self.result)?;
                } else if LINK_MAP_ENTRY_DUPLICATE.is_match(&line)
                    || LINK_MAP_EXTERN_SYMBOL.is_match(&line)
                {
                    // Ignore
                } else if let Some(captures) = SECTION_LAYOUT_START.captures(&line) {
                    self.switch_state(ProcessMapState::SectionLayout(SectionLayoutState {
                        current_section: captures["section"].to_string(),
                        has_link_map: self.has_link_map,
                        ..Default::default()
                    }))?;
                } else if MEMORY_MAP_START.is_match(&line) {
                    self.switch_state(ProcessMapState::MemoryMap)?;
                } else if LINKER_SYMBOLS_START.is_match(&line) {
                    self.switch_state(ProcessMapState::LinkerGeneratedSymbols)?;
                } else {
                    bail!("Unexpected line while processing map: '{line}'");
                }
            }
            ProcessMapState::SectionLayout(ref mut state) => {
                if let Some(captures) = SECTION_LAYOUT_SYMBOL.captures(&line) {
                    StateMachine::section_layout_entry(captures, state, &self.result)?;
                } else if let Some(captures) = SECTION_LAYOUT_START.captures(&line) {
                    self.switch_state(ProcessMapState::SectionLayout(SectionLayoutState {
                        current_section: captures["section"].to_string(),
                        has_link_map: self.has_link_map,
                        ..Default::default()
                    }))?;
                } else if SECTION_LAYOUT_HEADER.is_match(&line) {
                    // Ignore
                } else if MEMORY_MAP_START.is_match(&line) {
                    self.switch_state(ProcessMapState::MemoryMap)?;
                } else if LINKER_SYMBOLS_START.is_match(&line) {
                    self.switch_state(ProcessMapState::LinkerGeneratedSymbols)?;
                } else {
                    bail!("Unexpected line while processing map: '{line}'");
                }
            }
            ProcessMapState::MemoryMap => {
                if let Some(captures) = MEMORY_MAP_ENTRY.captures(&line) {
                    StateMachine::memory_map_entry(captures, &mut self.result)?;
                } else if LINKER_SYMBOLS_START.is_match(&line) {
                    self.switch_state(ProcessMapState::LinkerGeneratedSymbols)?;
                }
            }
            ProcessMapState::LinkerGeneratedSymbols => {
                if let Some(captures) = LINKER_SYMBOL_ENTRY.captures(&line) {
                    StateMachine::linker_symbol_entry(captures, &mut self.result)?;
                }
            }
        }
        Ok(())
    }

    fn switch_state(&mut self, new_state: ProcessMapState) -> Result<()> {
        let old_state = replace(&mut self.state, new_state);
        self.end_state(old_state)?;
        Ok(())
    }

    fn end_state(&mut self, old_state: ProcessMapState) -> Result<()> {
        match old_state {
            ProcessMapState::LinkMap(state) => {
                self.has_link_map = !state.last_symbol_name.is_empty();
            }
            ProcessMapState::SectionLayout(state) => {
                StateMachine::end_section_layout(state, &mut self.result)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn process_link_map_entry(
        captures: Captures,
        state: &mut LinkMapState,
        result: &mut MapInfo,
    ) -> Result<()> {
        let is_duplicate = &captures["sym"] == ">>>";
        let unit = captures["tu"].trim().to_string();
        let name = if is_duplicate {
            ensure!(!state.last_symbol_name.is_empty(), "Last name empty?");
            state.last_symbol_name.clone()
        } else {
            captures["sym"].to_string()
        };
        let symbol_ref = SymbolRef { name: name.clone(), unit: Some(unit.clone()) };
        let depth: usize = captures["depth"].parse()?;
        if depth > state.symbol_stack.len() {
            state.symbol_stack.push(symbol_ref.clone());
        } else if depth <= state.symbol_stack.len() {
            state.symbol_stack.truncate(depth - 1);
            state.symbol_stack.push(symbol_ref.clone());
        }
        // println!("Entry: {} ({})", name, tu);
        let kind = match &captures["type"] {
            "func" => SymbolKind::Function,
            "object" => SymbolKind::Object,
            "section" => SymbolKind::Section,
            "notype" => SymbolKind::NoType,
            kind => bail!("Unknown symbol type: {kind}"),
        };
        let visibility = match &captures["vis"] {
            "global" => SymbolVisibility::Global,
            "local" => SymbolVisibility::Local,
            "weak" => SymbolVisibility::Weak,
            visibility => bail!("Unknown symbol visibility: {visibility}"),
        };
        if !is_duplicate && state.symbol_stack.len() > 1 {
            let from = &state.symbol_stack[state.symbol_stack.len() - 2];
            result.entry_referenced_from.insert(symbol_ref.clone(), from.clone());
            result.entry_references.insert(from.clone(), symbol_ref.clone());
        }
        let mut should_insert = true;
        if let Some(symbol) = result.link_map_symbols.get(&symbol_ref) {
            if symbol.kind != kind {
                log::warn!(
                    "Kind mismatch for {}: was {:?}, now {:?}",
                    symbol.name,
                    symbol.kind,
                    kind
                );
            }
            if symbol.visibility != visibility {
                log::warn!(
                    "Visibility mismatch for {}: was {:?}, now {:?}",
                    symbol.name,
                    symbol.visibility,
                    visibility
                );
            }
            result.unit_entries.insert(unit.clone(), symbol_ref.clone());
            should_insert = false;
        }
        if should_insert {
            let demangled = demangle(&name, &DemangleOptions::default());
            result.link_map_symbols.insert(symbol_ref.clone(), SymbolEntry {
                name: name.clone(),
                demangled,
                kind,
                visibility,
                unit: Some(unit.clone()),
                address: 0,
                size: 0,
                align: None,
            });
            state.last_symbol_name = name;
            result.unit_entries.insert(unit, symbol_ref);
        }
        Ok(())
    }

    fn process_link_map_generated(
        captures: Captures,
        _state: &mut LinkMapState,
        result: &mut MapInfo,
    ) -> Result<()> {
        let name = captures["sym"].to_string();
        let demangled = demangle(&name, &DemangleOptions::default());
        let symbol_ref = SymbolRef { name: name.clone(), unit: None };
        result.link_map_symbols.insert(symbol_ref, SymbolEntry {
            name,
            demangled,
            kind: SymbolKind::NoType,
            visibility: SymbolVisibility::Global,
            unit: None,
            address: 0,
            size: 0,
            align: None,
        });
        Ok(())
    }

    fn end_section_layout(mut state: SectionLayoutState, entries: &mut MapInfo) -> Result<()> {
        // Resolve duplicate TUs
        let mut existing = HashSet::new();
        for idx in 0..state.units.len() {
            let (addr, unit) = &state.units[idx];
            // FIXME
            if
            /*state.current_section == ".bss" ||*/
            existing.contains(unit) {
                if
                /*state.current_section == ".bss" ||*/
                &state.units[idx - 1].1 != unit {
                    let new_name = format!("{unit}_{}_{:010X}", state.current_section, addr);
                    log::info!("Renaming {unit} to {new_name}");
                    for idx2 in 0..idx {
                        let (addr, n_unit) = &state.units[idx2];
                        if unit == n_unit {
                            let new_name =
                                format!("{n_unit}_{}_{:010X}", state.current_section, addr);
                            log::info!("Renaming 2 {n_unit} to {new_name}");
                            state.units[idx2].1 = new_name;
                            break;
                        }
                    }
                    state.units[idx].1 = new_name;
                }
            } else {
                existing.insert(unit.clone());
            }
        }
        if !state.symbols.is_empty() {
            entries.section_symbols.insert(state.current_section.clone(), state.symbols);
        }
        if !state.units.is_empty() {
            entries.section_units.insert(state.current_section.clone(), state.units);
        }
        // Set last section size
        // if let Some(last_unit) = state.section_units.last() {
        //     let last_unit = state.unit_override.as_ref().unwrap_or(last_unit);
        //     nested_try_insert(
        //         &mut entries.unit_section_ranges,
        //         last_unit.clone(),
        //         state.current_section.clone(),
        //         state.last_unit_start..state.last_section_end,
        //     )
        //     .with_context(|| {
        //         format!("TU '{}' already exists in section '{}'", last_unit, state.current_section)
        //     })?;
        // }
        Ok(())
    }

    fn section_layout_entry(
        captures: Captures,
        state: &mut SectionLayoutState,
        result: &MapInfo,
    ) -> Result<()> {
        if captures["rom_addr"].trim() == "UNUSED" {
            return Ok(());
        }

        let sym_name = captures["sym"].trim();
        if sym_name == "*fill*" {
            return Ok(());
        }

        let tu = captures["tu"].trim().to_string();
        if tu == "*fill*" || tu == "Linker Generated Symbol File" {
            return Ok(());
        }

        let address = u32::from_str_radix(captures["addr"].trim(), 16)?;
        let size = u32::from_str_radix(captures["size"].trim(), 16)?;
        let align =
            captures.name("align").and_then(|m| u32::from_str_radix(m.as_str().trim(), 16).ok());

        if state.current_unit.as_ref() != Some(&tu) || sym_name == state.current_section {
            state.current_unit = Some(tu.clone());
            state.units.push((address, tu.clone()));
            if sym_name == state.current_section {
                return Ok(());
            }
        }

        let symbol_ref = SymbolRef { name: sym_name.to_string(), unit: Some(tu.clone()) };
        let entry = if let Some(existing) = result.link_map_symbols.get(&symbol_ref) {
            SymbolEntry {
                name: existing.name.clone(),
                demangled: existing.demangled.clone(),
                kind: existing.kind,
                visibility: existing.visibility,
                unit: existing.unit.clone(),
                address,
                size,
                align,
            }
        } else {
            let mut visibility = if state.has_link_map {
                log::warn!(
                    "Symbol not in link map: {} ({}). Type and visibility unknown.",
                    sym_name,
                    tu,
                );
                SymbolVisibility::Local
            } else {
                SymbolVisibility::Unknown
            };
            let kind = if sym_name.starts_with('.') {
                visibility = SymbolVisibility::Local;
                SymbolKind::Section
            } else if size > 0 {
                if is_code_section(&state.current_section) {
                    SymbolKind::Function
                } else {
                    SymbolKind::Object
                }
            } else {
                SymbolKind::NoType
            };
            SymbolEntry {
                name: sym_name.to_string(),
                demangled: None,
                kind,
                visibility,
                unit: Some(tu.clone()),
                address,
                size,
                align,
            }
        };
        match state.symbols.entry(address) {
            btree_map::Entry::Occupied(e) => e.into_mut().push(entry),
            btree_map::Entry::Vacant(e) => {
                e.insert(vec![entry]);
            }
        }
        Ok(())
    }

    fn memory_map_entry(captures: Captures, entries: &mut MapInfo) -> Result<()> {
        let section = &captures["section"];
        let addr_str = &captures["addr"];
        if addr_str.is_empty() {
            // Stripped from DOL
            return Ok(());
        }
        let address = u32::from_str_radix(addr_str, 16)?;
        let size = u32::from_str_radix(&captures["size"], 16)?;
        let file_offset = u32::from_str_radix(&captures["offset"], 16)?;
        // log::info!("Memory map entry: {section} {address:#010X} {size:#010X} {file_offset:#010X}");
        entries.sections.insert(address, SectionInfo {
            name: section.to_string(),
            address,
            size,
            file_offset,
        });
        Ok(())
    }

    fn linker_symbol_entry(captures: Captures, result: &mut MapInfo) -> Result<()> {
        let name = &captures["name"];
        let address = u32::from_str_radix(&captures["addr"], 16)?;
        if address == 0 {
            return Ok(());
        }

        let symbol_ref = SymbolRef { name: name.to_string(), unit: None };
        if let Some(existing) = result.link_map_symbols.get_mut(&symbol_ref) {
            existing.address = address;
        } else {
            result.link_map_symbols.insert(symbol_ref, SymbolEntry {
                name: name.to_string(),
                demangled: demangle(name, &DemangleOptions::default()),
                kind: SymbolKind::NoType,
                visibility: SymbolVisibility::Global,
                unit: None,
                address,
                size: 0,
                align: None,
            });
        };
        // log::info!("Linker generated symbol: {} @ {:#010X}", name, address);
        Ok(())
    }
}

pub fn process_map<R: BufRead>(reader: R) -> Result<MapInfo> {
    let mut sm = StateMachine {
        state: ProcessMapState::None,
        result: Default::default(),
        has_link_map: false,
    };
    for result in reader.lines() {
        match result {
            Ok(line) => sm.process_line(line)?,
            Err(e) => return Err(Error::from(e)),
        }
    }
    let state = replace(&mut sm.state, ProcessMapState::None);
    sm.end_state(state)?;

    let entries = sm.result;
    // let section_order = resolve_section_order(&entries.address_to_symbol, &mut entries.symbols)?;
    // entries.symbol_order = section_order.symbol_order;
    // entries.unit_order = section_order.unit_order;
    Ok(entries)
}

pub fn apply_map_file<P: AsRef<Path>>(path: P, obj: &mut ObjInfo) -> Result<()> {
    let file = map_file(&path)?;
    let info = process_map(map_reader(&file))?;
    apply_map(&info, obj)
}

pub fn apply_map(result: &MapInfo, obj: &mut ObjInfo) -> Result<()> {
    for (_section_index, section) in obj.sections.iter_mut() {
        if let Some(info) = result.sections.get(&(section.address as u32)) {
            let kind = section_kind_for_section(&info.name)?;
            if section.section_known {
                if section.name != info.name {
                    log::warn!("Section mismatch: was {}, map says {}", section.name, info.name);
                }
                if section.kind != kind {
                    log::warn!(
                        "Section type mismatch: {} was {:?}, map says {:?}",
                        info.name,
                        section.kind,
                        kind
                    );
                }
            }
            // if section.size != info.size as u64 {
            //     log::warn!(
            //         "Section size mismatch: {} was {:#X}, map says {:#X}",
            //         info.name,
            //         section.size,
            //         info.size
            //     );
            // }
            // if section.file_offset != info.file_offset as u64 {
            //     log::warn!(
            //         "Section file offset mismatch: {} was {:#X}, map says {:#X}",
            //         info.name,
            //         section.file_offset,
            //         info.file_offset
            //     );
            // }
            section.name = info.name.clone();
            section.kind = kind;
            // section.size = info.size as u64;
            // section.file_offset = info.file_offset as u64;
            // section.original_address = info.address as u64;
            section.section_known = true;
        } else {
            log::warn!("Section {} @ {:#010X} not found in map", section.name, section.address);
        }
    }
    // Add section symbols
    for (section_name, symbol_map) in &result.section_symbols {
        let (section_index, _) = obj
            .sections
            .by_name(section_name)?
            .ok_or_else(|| anyhow!("Failed to locate section {section_name} from map"))?;
        for symbol_entry in symbol_map.values().flatten() {
            add_symbol(obj, symbol_entry, Some(section_index))?;
        }
    }
    // Add absolute symbols
    for symbol_entry in result.link_map_symbols.values().filter(|s| s.unit.is_none()) {
        add_symbol(obj, symbol_entry, None)?;
    }
    // Add splits
    let mut section_order: Vec<(String, Vec<String>)> = Vec::new();
    for (section, unit_order) in &result.section_units {
        let mut units = Vec::new();
        let mut existing = HashSet::new();
        for (_addr, unit) in unit_order {
            let unit = unit.clone();
            if !existing.contains(&unit) {
                units.push(unit.clone());
                existing.insert(unit.clone());
            }
            // obj.splits.nested_push(*addr, ObjSplit {
            //     unit,
            //     end: 0, // TODO?
            //     align: None,
            //     common: false, // TODO?
            //     autogenerated: false,
            // });
        }
        section_order.push((section.clone(), units));
    }
    // TODO
    // log::info!("Section order: {:#?}", section_order);
    // obj.link_order = resolve_link_order(&section_order)?;
    Ok(())
}

fn add_symbol(obj: &mut ObjInfo, symbol_entry: &SymbolEntry, section: Option<usize>) -> Result<()> {
    let demangled_name = demangle(&symbol_entry.name, &DemangleOptions::default());
    obj.add_symbol(
        ObjSymbol {
            name: symbol_entry.name.clone(),
            demangled_name,
            address: symbol_entry.address as u64,
            section,
            size: symbol_entry.size as u64,
            size_known: symbol_entry.size != 0,
            flags: ObjSymbolFlagSet(match symbol_entry.visibility {
                SymbolVisibility::Unknown => Default::default(),
                SymbolVisibility::Global => ObjSymbolFlags::Global.into(),
                SymbolVisibility::Local => ObjSymbolFlags::Local.into(),
                SymbolVisibility::Weak => ObjSymbolFlags::Weak.into(),
            }),
            kind: match symbol_entry.kind {
                SymbolKind::Function => ObjSymbolKind::Function,
                SymbolKind::Object => ObjSymbolKind::Object,
                SymbolKind::Section => ObjSymbolKind::Section,
                SymbolKind::NoType => ObjSymbolKind::Unknown,
            },
            align: None,
            data_kind: Default::default(),
        },
        true,
    )?;
    Ok(())
}
