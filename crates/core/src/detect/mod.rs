//! Detección: superbloque, features, qué modos de copia son seguros y
//! capas de bloque (LUKS/LVM) bajo el sistema de archivos.

pub mod blockdev;
pub mod csum;
pub mod modes;
pub mod superblock;

pub use blockdev::block_stack;
pub use superblock::{read_all_copies, SuperblockExt};
