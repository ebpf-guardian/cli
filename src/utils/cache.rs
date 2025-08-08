use std::fs;
use std::path::{Path, PathBuf};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use anyhow::{Result, Context};

/// Cache entry for a scanned file
#[derive(Debug, Serialize, Deserialize)]
pub struct CacheEntry {
    /// SHA256 hash of the file
    pub file_hash: String,
    /// Timestamp of last scan
    pub timestamp: String,
    /// Cached scan results
    pub scan_results: crate::analyzer::ScanSummary,
}

/// Manages the cache for scanned files
pub struct Cache {
    cache_dir: PathBuf,
}

impl Cache {
    /// Creates a new cache instance
    pub fn new(cache_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&cache_dir)
            .context("Failed to create cache directory")?;
        Ok(Self { cache_dir })
    }
    
    /// Gets cached results for a file if available and unchanged
    pub fn get(&self, file_path: &Path) -> Result<Option<CacheEntry>> {
        let cache_path = self.get_cache_path(file_path);
        
        // If cache file doesn't exist, return None
        if !cache_path.exists() {
            return Ok(None);
        }
        
        // Read and parse cache entry
        let cache_content = fs::read_to_string(&cache_path)
            .context("Failed to read cache file")?;
        let entry: CacheEntry = serde_json::from_str(&cache_content)
            .context("Failed to parse cache entry")?;
            
        // Calculate current file hash
        let current_hash = self.calculate_file_hash(file_path)?;
        
        // Return cached results if hash matches
        if entry.file_hash == current_hash {
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }
    
    /// Stores scan results in cache
    pub fn store(&self, file_path: &Path, results: &crate::analyzer::ScanSummary) -> Result<()> {
        let cache_path = self.get_cache_path(file_path);
        
        let entry = CacheEntry {
            file_hash: self.calculate_file_hash(file_path)?,
            timestamp: chrono::Utc::now().to_rfc3339(),
            scan_results: results.clone(),
        };
        
        let cache_content = serde_json::to_string_pretty(&entry)
            .context("Failed to serialize cache entry")?;
            
        fs::write(&cache_path, cache_content)
            .context("Failed to write cache file")
    }
    
    /// Calculates SHA256 hash of a file
    fn calculate_file_hash(&self, file_path: &Path) -> Result<String> {
        let mut file = fs::File::open(file_path)
            .context("Failed to open file for hashing")?;
        let mut hasher = Sha256::new();
        std::io::copy(&mut file, &mut hasher)
            .context("Failed to read file for hashing")?;
        Ok(format!("{:x}", hasher.finalize()))
    }
    
    /// Gets cache file path for a given input file
    fn get_cache_path(&self, file_path: &Path) -> PathBuf {
        let file_name = file_path.file_name()
            .unwrap_or_default()
            .to_string_lossy();
        self.cache_dir.join(format!("{}.cache.json", file_name))
    }
}