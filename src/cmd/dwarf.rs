use std::{
    collections::{btree_map, BTreeMap},
    io::{Cursor, Write},
    path::PathBuf,
};

use anyhow::{anyhow, bail, Result};
use argp::FromArgs;
use object::{elf, Object, ObjectSection, ObjectSymbol, RelocationKind, RelocationTarget, Section};

use crate::util::{
    dwarf::{
        process_compile_unit, process_cu_tag, read_debug_section, should_skip_tag, tag_type_string,
        AttributeKind, TagKind,
    },
    file::{buf_writer, map_file},
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing DWARF 1.1 information.
#[argp(subcommand, name = "dwarf")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Dump(DumpArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Dumps DWARF 1.1 info from an object or archive.
#[argp(subcommand, name = "dump")]
pub struct DumpArgs {
    #[argp(positional)]
    /// Input object. (ELF or archive)
    in_file: PathBuf,
    #[argp(option, short = 'o')]
    /// Output directory.
    output_dir: PathBuf,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Dump(c_args) => dump(c_args),
    }
}

fn dump(args: DumpArgs) -> Result<()> {
    let file = map_file(&args.in_file)?;
    let buf = file.as_slice();

    let obj_file = object::read::File::parse(buf)?;
    let debug_section = obj_file
        .section_by_name(".debug")
        .ok_or_else(|| anyhow!("Failed to locate .debug section"))?;

    dump_debug_section(args.output_dir, &obj_file, debug_section)?;
    Ok(())
}

fn dump_debug_section(
    output_dir: PathBuf,
    obj_file: &object::File<'_>,
    debug_section: Section,
) -> Result<()> {
    let mut data = debug_section.uncompressed_data()?.into_owned();

    // Apply relocations to data
    for (addr, reloc) in debug_section.relocations() {
        match reloc.kind() {
            RelocationKind::Absolute | RelocationKind::Elf(elf::R_PPC_UADDR32) => {
                let target = match reloc.target() {
                    RelocationTarget::Symbol(symbol_idx) => {
                        let symbol = obj_file.symbol_by_index(symbol_idx)?;
                        (symbol.address() as i64 + reloc.addend()) as u32
                    }
                    _ => bail!("Invalid .debug relocation target"),
                };
                data[addr as usize..addr as usize + 4].copy_from_slice(&target.to_be_bytes());
            }
            RelocationKind::Elf(elf::R_PPC_NONE) => {}
            _ => bail!("Unhandled .debug relocation type {:?}", reloc.kind()),
        }
    }

    let mut reader = Cursor::new(&*data);
    let info = read_debug_section(&mut reader, obj_file.endianness().into())?;

    for (&addr, tag) in &info.tags {
        log::debug!("{}: {:?}", addr, tag);
    }

    let mut units = Vec::<String>::new();
    if let Some((_, mut tag)) = info.tags.first_key_value() {
        loop {
            match tag.kind {
                TagKind::Padding => {
                    // TODO
                }
                TagKind::CompileUnit => {
                    let unit = process_compile_unit(tag)?;
                    if units.contains(&unit.name) {
                        // log::warn!("Duplicate unit '{}'", unit.name);
                    } else {
                        units.push(unit.name.clone());
                    }

                    let name = unit.name.clone();
                    let name = name
                        .trim_start_matches("C:\\HOMEBOY\\STEPHEN\\Japanese Ocarina\\")
                        .replace('\\', "/");

                    let mut w = buf_writer(&output_dir.join(name))?;

                    writeln!(w, "/*\n    Compile unit: {}", unit.name)?;
                    if let Some(producer) = unit.producer {
                        writeln!(w, "    Producer: {}", producer)?;
                    }
                    if let Some(language) = unit.language {
                        writeln!(w, "    Language: {}", language)?;
                    }
                    if let (Some(start), Some(end)) = (unit.start_address, unit.end_address) {
                        writeln!(w, "    Code range: {:#010X} -> {:#010X}", start, end)?;
                    }
                    writeln!(w, "*/")?;
                    writeln!(w)?;
                    writeln!(w, "#include \"types.h\"")?;
                    writeln!(w)?;

                    let children = tag.children(&info.tags);
                    let mut typedefs = BTreeMap::<u32, Vec<u32>>::new();
                    for child in children {
                        let tag_type = match process_cu_tag(&info, child) {
                            Ok(tag_type) => tag_type,
                            Err(e) => {
                                log::error!(
                                    "Failed to process tag {} (unit {}): {}",
                                    child.key,
                                    unit.name,
                                    e
                                );
                                writeln!(
                                    w,
                                    "// ERROR: Failed to process tag {} ({:?})",
                                    child.key, child.kind
                                )?;
                                continue;
                            }
                        };
                        if should_skip_tag(&tag_type) {
                            continue;
                        }
                        match tag_type_string(&info, &typedefs, &tag_type) {
                            Ok(s) => writeln!(w, "{}", s)?,
                            Err(e) => {
                                log::error!(
                                    "Failed to emit tag {} (unit {}): {}",
                                    child.key,
                                    unit.name,
                                    e
                                );
                                writeln!(
                                    w,
                                    "// ERROR: Failed to emit tag {} ({:?})",
                                    child.key, child.kind
                                )?;
                                continue;
                            }
                        }

                        if let TagKind::Typedef = child.kind {
                            // TODO fundamental typedefs?
                            if let Some(ud_type_ref) =
                                child.reference_attribute(AttributeKind::UserDefType)
                            {
                                match typedefs.entry(ud_type_ref) {
                                    btree_map::Entry::Vacant(e) => {
                                        e.insert(vec![child.key]);
                                    }
                                    btree_map::Entry::Occupied(e) => {
                                        e.into_mut().push(child.key);
                                    }
                                }
                            }
                        }
                    }
                }
                kind => bail!("Unhandled root tag type {:?}", kind),
            }

            if let Some(next) = tag.next_sibling(&info.tags) {
                tag = next;
            } else {
                break;
            }
        }
    }
    // log::info!("Link order:");
    // for x in units {
    //     log::info!("{}", x);
    // }
    Ok(())
}
