/// Aegis TUI theme — uses ANSI 256 + basic colors for universal terminal support.
/// RGB colors don't render on many terminals. These always work.
use ratatui::style::Color;

// Backgrounds (256-color indexed: 232-255 are grayscale)
pub const BG: Color = Color::Indexed(233);        // very dark gray
pub const BG_CARD: Color = Color::Indexed(234);    // slightly lighter
pub const BG_ROW_ALT: Color = Color::Indexed(235); // alternating row
pub const BG_HEADER: Color = Color::Indexed(234);
pub const BG_SELECTED: Color = Color::Indexed(237);
pub const BORDER: Color = Color::Indexed(238);
pub const BORDER_DIM: Color = Color::Indexed(236);

// Text (256-color indexed grayscale)
pub const TEXT: Color = Color::Indexed(250);        // light gray
pub const TEXT_DIM: Color = Color::Indexed(243);    // medium gray
pub const TEXT_BRIGHT: Color = Color::Indexed(255);  // near-white

// Accents — basic ANSI colors, guaranteed to render correctly
pub const GREEN: Color = Color::LightGreen;         // ALLOW only
pub const RED: Color = Color::LightRed;             // BLOCK only
pub const CYAN: Color = Color::LightCyan;           // structure, headers
pub const YELLOW: Color = Color::LightYellow;       // HTTP methods
pub const PURPLE: Color = Color::LightMagenta;      // source labels
