use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const DEFAULT_MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;
pub const DEFAULT_MAX_LOG_BACKUPS: usize = 2;

pub const APP_LOG_FILE_NAME: &str = "freeton-app.log";
pub const SERVICE_LOG_FILE_NAME: &str = "freeton-service.log";
pub const TUNNEL_LOG_FILE_NAME: &str = "freeton-tunnel.log";

pub fn resolve_app_log_dir_from_env(
    local_app_data: Option<OsString>,
    temp_dir: Option<OsString>,
) -> PathBuf {
    let base = local_app_data
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| temp_dir.filter(|v| !v.is_empty()).map(PathBuf::from))
        .unwrap_or_else(env::temp_dir);
    base.join("FreetonVPN").join("logs")
}

/// Returns `%LOCALAPPDATA%\FreetonVPN\logs` (falling back to `%TEMP%\FreetonVPN\logs`).
pub fn app_log_dir() -> PathBuf {
    resolve_app_log_dir_from_env(env::var_os("LOCALAPPDATA"), env::var_os("TEMP"))
}

pub fn resolve_service_log_dir_from_env(program_data: Option<OsString>) -> PathBuf {
    let base = program_data
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("FreetonVPN").join("logs")
}

/// Returns `%ProgramData%\FreetonVPN\logs` (falling back to `C:\ProgramData\FreetonVPN\logs`).
pub fn service_log_dir() -> PathBuf {
    resolve_service_log_dir_from_env(env::var_os("ProgramData"))
}

#[derive(Debug)]
struct RollingFileInner {
    path: PathBuf,
    max_bytes: u64,
    max_backups: usize,
    file: Option<File>,
    bytes_written: u64,
}

impl RollingFileInner {
    fn open_current(&mut self) -> io::Result<()> {
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        self.file = Some(file);
        self.bytes_written = len;
        Ok(())
    }

    fn backup_path(&self, index: usize) -> PathBuf {
        let name = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("freeton.log");
        self.path.with_file_name(format!("{name}.{index}"))
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file.take();
        if self.max_backups == 0 {
            let _ = fs::remove_file(&self.path);
            return self.open_current();
        }

        let oldest = self.backup_path(self.max_backups);
        let _ = fs::remove_file(oldest);

        for idx in (1..self.max_backups).rev() {
            let src = self.backup_path(idx);
            let dst = self.backup_path(idx + 1);
            if src.exists() {
                let _ = fs::rename(&src, &dst);
            }
        }
        if self.path.exists() {
            let _ = fs::rename(&self.path, self.backup_path(1));
        }

        self.open_current()
    }

    fn write_bytes(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.file.is_none() {
            self.open_current()?;
        }
        if self.max_bytes > 0
            && self.bytes_written > 0
            && self.bytes_written.saturating_add(buf.len() as u64) > self.max_bytes
        {
            self.rotate()?;
        }

        if let Some(file) = self.file.as_mut() {
            file.write_all(buf)?;
            self.bytes_written = self.bytes_written.saturating_add(buf.len() as u64);
        }
        Ok(buf.len())
    }

    fn flush_file(&mut self) -> io::Result<()> {
        if let Some(file) = self.file.as_mut() {
            file.flush()?;
        }
        Ok(())
    }
}

/// Thread-safe size-rotating file writer for `tracing_subscriber` without external crates.
#[derive(Debug, Clone)]
pub struct RollingFileWriter {
    inner: Arc<Mutex<RollingFileInner>>,
}

impl RollingFileWriter {
    pub fn open(
        path: impl Into<PathBuf>,
        max_bytes: u64,
        max_backups: usize,
    ) -> io::Result<Self> {
        let mut inner = RollingFileInner {
            path: path.into(),
            max_bytes,
            max_backups,
            file: None,
            bytes_written: 0,
        };
        inner.open_current()?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    pub fn path(&self) -> PathBuf {
        self.inner
            .lock()
            .expect("rolling log writer lock poisoned")
            .path
            .clone()
    }
}

impl Write for RollingFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("rolling log writer lock poisoned"))?;
        inner.write_bytes(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("rolling log writer lock poisoned"))?;
        inner.flush_file()
    }
}

/// Returns a display-safe UTF-8 path string without UNC `\\?\` prefix for Windows shells/UI.
pub fn clean_display_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    raw.strip_prefix(r"\\?\").unwrap_or(&raw).to_owned()
}

fn escape_ps_single_quoted(value: &str) -> String {
    value.replace('\'', "''")
}

/// Builds a self-contained PowerShell script that tails app, service, and tunnel logs
/// concurrently in real time using shared read-only file handles (`FileShare.ReadWrite, Delete`)
/// so log rotation is never blocked.
pub fn build_realtime_log_viewer_script(
    app_log: &Path,
    service_log: &Path,
    tunnel_log: &Path,
) -> String {
    let app = escape_ps_single_quoted(&clean_display_path(app_log));
    let svc = escape_ps_single_quoted(&clean_display_path(service_log));
    let tun = escape_ps_single_quoted(&clean_display_path(tunnel_log));
    format!(
        r#"$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = 'Freeton VPN - Realtime Log (Dev Mode)'
$sources = @(
    @{{ Tag = 'APP'; Path = '{app}'; Color = 'Cyan'; Pos = 0L }},
    @{{ Tag = 'SVC'; Path = '{svc}'; Color = 'Yellow'; Pos = 0L }},
    @{{ Tag = 'TUN'; Path = '{tun}'; Color = 'Green'; Pos = 0L }}
)
Write-Host '=== Freeton VPN Realtime Log Viewer (Dev Mode) ===' -ForegroundColor Magenta
foreach ($s in $sources) {{
    Write-Host ("  [{{0}}] {{1}}" -f $s.Tag, $s.Path) -ForegroundColor DarkGray
}}
Write-Host '--- Lich su gan nhat ---' -ForegroundColor DarkGray
foreach ($s in $sources) {{
    if (Test-Path -LiteralPath $s.Path) {{
        $tailLines = Get-Content -LiteralPath $s.Path -Tail 25 -Encoding UTF8
        foreach ($line in $tailLines) {{
            if ($line) {{
                $col = if ($line -match '\bERROR\b') {{ 'Red' }} elseif ($line -match '\bWARN\b') {{ 'DarkYellow' }} else {{ $s.Color }}
                Write-Host ("[{{0}}] {{1}}" -f $s.Tag, $line) -ForegroundColor $col
            }}
        }}
        $s.Pos = (Get-Item -LiteralPath $s.Path).Length
    }}
}}
Write-Host '--- Dang theo doi log realtime (nhan Ctrl+C hoac dong cua so de thoat) ---' -ForegroundColor DarkGray
while ($true) {{
    $hadData = $false
    foreach ($s in $sources) {{
        if (-not (Test-Path -LiteralPath $s.Path)) {{ continue }}
        $len = (Get-Item -LiteralPath $s.Path).Length
        if ($len -lt $s.Pos) {{ $s.Pos = 0L }}
        if ($len -gt $s.Pos) {{
            $fs = [System.IO.File]::Open($s.Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
            try {{
                $null = $fs.Seek($s.Pos, [System.IO.SeekOrigin]::Begin)
                $avail = [int]($len - $s.Pos)
                if ($avail -gt 0) {{
                    $buf = New-Object byte[] $avail
                    $read = $fs.Read($buf, 0, $avail)
                    if ($read -gt 0) {{
                        $lastNl = [Array]::LastIndexOf($buf, [byte]10, $read - 1)
                        if ($lastNl -ge 0) {{
                            $completeLen = $lastNl + 1
                            $chunk = [System.Text.Encoding]::UTF8.GetString($buf, 0, $completeLen)
                            foreach ($line in ($chunk -split "`r?`n")) {{
                                if ($line.Length -gt 0) {{
                                    $col = if ($line -match '\bERROR\b') {{ 'Red' }} elseif ($line -match '\bWARN\b') {{ 'DarkYellow' }} else {{ $s.Color }}
                                    Write-Host ("[{{0}}] {{1}}" -f $s.Tag, $line) -ForegroundColor $col
                                    $hadData = $true
                                }}
                            }}
                            $s.Pos = $s.Pos + $completeLen
                        }}
                    }}
                }}
            }} finally {{
                $fs.Dispose()
            }}
        }}
    }}
    if (-not $hadData) {{ Start-Sleep -Milliseconds 150 }}
}}"#
    )
}

/// Encodes a PowerShell script as UTF-16LE Base64 suitable for `-EncodedCommand`.
pub fn encode_powershell_encoded_command(script: &str) -> String {
    let mut utf16_bytes = Vec::with_capacity(script.len() * 2);
    for unit in script.encode_utf16() {
        utf16_bytes.extend_from_slice(&unit.to_le_bytes());
    }
    BASE64_STANDARD.encode(&utf16_bytes)
}

pub const RINGLOGGER_MAGIC: u32 = 0x0bad_babe;
pub const RINGLOGGER_MAX_LINES: usize = 2048;
pub const RINGLOGGER_MAX_LINE_BYTES: usize = 512;
pub const RINGLOGGER_HEADER_BYTES: usize = 8;
pub const RINGLOGGER_SLOT_BYTES: usize = 8 + RINGLOGGER_MAX_LINE_BYTES;
pub const RINGLOGGER_FILE_BYTES: usize =
    RINGLOGGER_HEADER_BYTES + RINGLOGGER_MAX_LINES * RINGLOGGER_SLOT_BYTES;

/// Decoded single line from WireGuard Windows `log.bin` (`ringlogger`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RinglogEntry {
    pub index: u32,
    pub time_ns: i64,
    pub text: String,
}

fn civil_from_days(days_since_unix_epoch: i64) -> (i64, u32, u32) {
    // Howard Hinnant's Euclidean civil-from-days algorithm.
    let z = days_since_unix_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m as u32, d as u32)
}

/// Formats a Unix timestamp in nanoseconds as `YYYY-MM-DDTHH:MM:SS.ffffffZ` matching `tracing`.
pub fn format_unix_ns_utc(time_ns: i64) -> String {
    let clamped = time_ns.max(0) as u128;
    let total_secs = (clamped / 1_000_000_000) as i64;
    let micros = ((clamped % 1_000_000_000) / 1_000) as u32;
    let days = total_secs.div_euclid(86_400);
    let secs_of_day = total_secs.rem_euclid(86_400) as u32;
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{micros:06}Z")
}

/// Parses newly written WireGuard `ringlogger` entries from `data` starting at `cursor`.
/// Returns `(entries, new_cursor)` so incomplete in-flight slots are retried on the next read.
pub fn read_ringlogger_bytes_since(
    data: &[u8],
    cursor: Option<u32>,
) -> (Vec<RinglogEntry>, Option<u32>) {
    if data.len() < RINGLOGGER_FILE_BYTES {
        return (Vec::new(), cursor);
    }
    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]));
    if magic != RINGLOGGER_MAGIC {
        return (Vec::new(), cursor);
    }
    let next_index = u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4]));
    let start_index = match cursor {
        Some(prev) => {
            let delta = next_index.wrapping_sub(prev);
            if delta == 0 {
                return (Vec::new(), Some(next_index));
            }
            if delta > RINGLOGGER_MAX_LINES as u32 {
                next_index.wrapping_sub(RINGLOGGER_MAX_LINES as u32)
            } else {
                prev
            }
        }
        None => next_index.saturating_sub(RINGLOGGER_MAX_LINES as u32),
    };

    let count = next_index.wrapping_sub(start_index).min(RINGLOGGER_MAX_LINES as u32);
    let mut entries = Vec::new();
    let mut advanced_to = start_index;

    for offset in 0..count {
        let idx = start_index.wrapping_add(offset);
        let slot = (idx as usize) % RINGLOGGER_MAX_LINES;
        let base = RINGLOGGER_HEADER_BYTES + slot * RINGLOGGER_SLOT_BYTES;
        let slot_bytes = &data[base..base + RINGLOGGER_SLOT_BYTES];
        let time_ns = i64::from_le_bytes(slot_bytes[0..8].try_into().unwrap_or([0; 8]));
        let text_bytes = &slot_bytes[8..];
        if time_ns <= 0 || text_bytes[0] == 0 {
            // Stop advancing before an unfinished or zeroed slot unless scanning initial buffer.
            if cursor.is_some() {
                break;
            }
            advanced_to = idx.wrapping_add(1);
            continue;
        }
        let nul_pos = text_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(RINGLOGGER_MAX_LINE_BYTES);
        let raw_text = String::from_utf8_lossy(&text_bytes[..nul_pos]).trim().to_owned();
        let cleaned = raw_text
            .strip_prefix("[TUN] ")
            .unwrap_or(&raw_text)
            .to_owned();
        if !cleaned.is_empty() {
            entries.push(RinglogEntry {
                index: idx,
                time_ns,
                text: cleaned,
            });
        }
        advanced_to = idx.wrapping_add(1);
    }

    (entries, Some(advanced_to))
}

/// Stateful tailer that mirrors WireGuard `log.bin` entries into a text `RollingFileWriter`.
#[derive(Debug)]
pub struct WireGuardRinglogMirror {
    log_bin_path: PathBuf,
    writer: RollingFileWriter,
    cursor: Option<u32>,
}

impl WireGuardRinglogMirror {
    pub fn new(log_bin_path: PathBuf, writer: RollingFileWriter) -> Self {
        Self {
            log_bin_path,
            writer,
            cursor: None,
        }
    }

    /// Anchors cursor at current `nextIndex` in `log.bin` (if valid) before a new tunnel starts,
    /// so stale lines from past runs are not duplicated.
    pub fn snap_cursor_to_tail(&mut self) {
        if let Ok(data) = fs::read(&self.log_bin_path) {
            if data.len() >= RINGLOGGER_FILE_BYTES
                && u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4])) == RINGLOGGER_MAGIC
            {
                let next_idx = u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4]));
                self.cursor = Some(next_idx);
                return;
            }
        }
        self.cursor = Some(0);
    }

    /// Reads any newly appended WireGuard `log.bin` lines and writes them into the rotated log file.
    pub fn poll_and_mirror(&mut self) -> io::Result<usize> {
        let data = match fs::read(&self.log_bin_path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(err) => return Err(err),
        };
        let (entries, next_cursor) = read_ringlogger_bytes_since(&data, self.cursor);
        self.cursor = next_cursor;
        if entries.is_empty() {
            return Ok(0);
        }
        let mut out = String::new();
        for entry in &entries {
            let ts = format_unix_ns_utc(entry.time_ns);
            out.push_str(&format!("{ts}  INFO WireGuardNT: {}\n", entry.text));
        }
        self.writer.write_all(out.as_bytes())?;
        self.writer.flush()?;
        Ok(entries.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        env::temp_dir().join(format!("{label}_{}_{}", std::process::id(), nanos))
    }

    #[test]
    fn test_log_dir_resolution_prefers_localappdata_and_programdata() {
        assert_eq!(
            resolve_app_log_dir_from_env(
                Some(OsString::from(r"C:\Users\Alice\AppData\Local")),
                Some(OsString::from(r"C:\Temp")),
            ),
            PathBuf::from(r"C:\Users\Alice\AppData\Local\FreetonVPN\logs")
        );
        assert_eq!(
            resolve_app_log_dir_from_env(None, Some(OsString::from(r"C:\Temp"))),
            PathBuf::from(r"C:\Temp\FreetonVPN\logs")
        );
        assert_eq!(
            resolve_service_log_dir_from_env(Some(OsString::from(r"D:\ProgramData"))),
            PathBuf::from(r"D:\ProgramData\FreetonVPN\logs")
        );
        assert_eq!(
            resolve_service_log_dir_from_env(None),
            PathBuf::from(r"C:\ProgramData\FreetonVPN\logs")
        );
    }

    #[test]
    fn test_rolling_file_writer_rotates_and_caps_backups() {
        let dir = unique_temp_dir("freeton_log_rotate_test");
        let log_path = dir.join("freeton-app.log");
        let mut writer = RollingFileWriter::open(&log_path, 30, 2).expect("open rolling writer");

        writer.write_all(b"line-1-aaaaaaaaaaaa\n").expect("write 1");
        writer.write_all(b"line-2-bbbbbbbbbbbb\n").expect("write 2");
        writer.write_all(b"line-3-cccccccccccc\n").expect("write 3");
        writer.write_all(b"line-4-dddddddddddd\n").expect("write 4");
        writer.flush().expect("flush");

        let active = fs::read_to_string(&log_path).expect("read active");
        let backup1 = fs::read_to_string(dir.join("freeton-app.log.1")).expect("read .1");
        let backup2 = fs::read_to_string(dir.join("freeton-app.log.2")).expect("read .2");
        assert!(!dir.join("freeton-app.log.3").exists());
        assert_eq!(active, "line-4-dddddddddddd\n");
        assert_eq!(backup1, "line-3-cccccccccccc\n");
        assert_eq!(backup2, "line-2-bbbbbbbbbbbb\n");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_realtime_log_viewer_script_and_encoded_command() {
        let script = build_realtime_log_viewer_script(
            Path::new(r"\\?\C:\Users\O'Brien\AppData\Local\FreetonVPN\logs\freeton-app.log"),
            Path::new(r"C:\ProgramData\FreetonVPN\logs\freeton-service.log"),
            Path::new(r"C:\ProgramData\FreetonVPN\logs\freeton-tunnel.log"),
        );
        assert!(script.contains(r"C:\Users\O''Brien\AppData\Local\FreetonVPN\logs\freeton-app.log"));
        assert!(script.contains("freeton-service.log"));
        assert!(script.contains("freeton-tunnel.log"));
        assert!(script.contains("FileShare]::ReadWrite"));

        let encoded = encode_powershell_encoded_command("Write-Host 'ok'");
        let decoded_bytes = BASE64_STANDARD.decode(&encoded).expect("valid base64");
        let utf16: Vec<u16> = decoded_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(String::from_utf16(&utf16).expect("utf16"), "Write-Host 'ok'");
    }

    fn write_synthetic_slot(buf: &mut [u8], slot: usize, time_ns: i64, text: &str) {
        let base = RINGLOGGER_HEADER_BYTES + slot * RINGLOGGER_SLOT_BYTES;
        buf[base..base + 8].copy_from_slice(&time_ns.to_le_bytes());
        buf[base + 8..base + RINGLOGGER_SLOT_BYTES].fill(0);
        let bytes = text.as_bytes();
        let copy_len = bytes.len().min(RINGLOGGER_MAX_LINE_BYTES - 1);
        buf[base + 8..base + 8 + copy_len].copy_from_slice(&bytes[..copy_len]);
    }

    #[test]
    fn test_ringlogger_reader_decodes_wraps_and_mirrors_log_bin() {
        let dir = unique_temp_dir("freeton_ringlogger_test");
        fs::create_dir_all(&dir).expect("mkdir");
        let log_bin = dir.join("log.bin");
        let mirror_log = dir.join("freeton-tunnel.log");

        let mut buf = vec![0u8; RINGLOGGER_FILE_BYTES];
        buf[0..4].copy_from_slice(&RINGLOGGER_MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&1u32.to_le_bytes());
        write_synthetic_slot(
            &mut buf,
            0,
            1_700_000_000_123_456_000,
            "[TUN] [FreetonVPN] Old run line",
        );
        fs::write(&log_bin, &buf).expect("seed log.bin");

        let writer = RollingFileWriter::open(&mirror_log, 1024 * 1024, 1).expect("open mirror");
        let mut mirror = WireGuardRinglogMirror::new(log_bin.clone(), writer);
        mirror.snap_cursor_to_tail();
        assert_eq!(mirror.poll_and_mirror().expect("no new lines yet"), 0);

        // Append two new slots wrapping past RINGLOGGER_MAX_LINES (simulate wrap: cursor=1, next=2049 -> slots 1..=2048).
        buf[4..8].copy_from_slice(&3u32.to_le_bytes());
        write_synthetic_slot(
            &mut buf,
            1,
            1_700_000_001_000_000_000,
            "[TUN] [FreetonVPN] Using WireGuardNT/0.10",
        );
        write_synthetic_slot(
            &mut buf,
            2,
            1_700_000_002_500_000_000,
            "[TUN] [FreetonVPN] Startup complete",
        );
        fs::write(&log_bin, &buf).expect("update log.bin");

        assert_eq!(mirror.poll_and_mirror().expect("mirror 2 lines"), 2);
        assert_eq!(mirror.poll_and_mirror().expect("no duplicate emit"), 0);

        let content = fs::read_to_string(&mirror_log).expect("read mirrored log");
        assert!(!content.contains("Old run line"));
        assert!(content.contains("2023-11-14T22:13:21.000000Z  INFO WireGuardNT: [FreetonVPN] Using WireGuardNT/0.10"));
        assert!(content.contains("2023-11-14T22:13:22.500000Z  INFO WireGuardNT: [FreetonVPN] Startup complete"));

        let _ = fs::remove_dir_all(&dir);
    }
}
