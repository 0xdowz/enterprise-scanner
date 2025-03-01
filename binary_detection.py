import os
import magic
import math
import hashlib
from typing import List, Dict, Optional, Tuple
from rich.console import Console
from rich.progress import track

class BinaryDetector:
    def __init__(self):
        self.console = Console()
        self.mime = magic.Magic(mime=True)
        self.binary_extensions = {
            # Executable and libraries
            '.exe', '.dll', '.so', '.dylib', '.bin',
            # Java
            '.jar', '.war', '.ear', '.class',
            # Python
            '.pyc', '.pyo', '.pyd',
            # Object files
            '.obj', '.o',
            # Additional binary formats
            '.sys', '.drv', '.ocx', '.com',  # Windows system files
            '.ko', '.mod',  # Linux kernel modules
            '.elf',  # Executable and Linkable Format
            '.msi', '.cab',  # Windows installers
            '.iso', '.img',  # Disk images
            '.apk', '.aab',  # Android packages
            '.dmg',  # macOS disk image
            '.lib', '.a'  # Static libraries
        }
        
        # Known malicious signatures (hex patterns)
        self.malicious_signatures = {
            b'\x4D\x5A\x90\x00': 'Windows PE executable',
            b'\x7F\x45\x4C\x46': 'ELF executable',
            b'\xCA\xFE\xBA\xBE': 'Java class file',
            b'\xCF\xFA\xED\xFE': 'Mach-O binary (macOS)',
            b'\x50\x4B\x03\x04': 'ZIP archive (may contain malicious code)',
            b'\x52\x61\x72\x21': 'RAR archive (may contain malicious code)'
        }

    def is_binary_file(self, file_path: str) -> bool:
        """Check if a file is binary based on its extension and content"""
        try:
            # Check file extension first
            ext = os.path.splitext(file_path)[1].lower()
            if ext in self.binary_extensions:
                return True

            # Check MIME type
            mime_type = self.mime.from_file(file_path)
            return not mime_type.startswith(('text/', 'application/json', 'application/xml'))

        except Exception as e:
            self.console.print(f"[yellow]Warning: Could not determine if {file_path} is binary: {str(e)}[/yellow]")
            return False

    def scan_directory(self, directory: str) -> Dict[str, List[str]]:
        """Scan a directory for binary files"""
        result = {
            'binary_files': [],
            'text_files': []
        }

        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if self.is_binary_file(file_path):
                    result['binary_files'].append(file_path)
                else:
                    result['text_files'].append(file_path)

        return result

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data"""
        if not data:
            return 0.0
            
        entropy = 0.0
        byte_counts = {}
        data_len = len(data)
        
        # Count occurrences of each byte
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        # Calculate entropy
        for count in byte_counts.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
            
        return entropy
    
    def check_signatures(self, data: bytes) -> List[Dict]:
        """Check for known malicious signatures in binary data"""
        findings = []
        
        for signature, description in self.malicious_signatures.items():
            if signature in data[:1024]:  # Check first 1KB for efficiency
                findings.append({
                    'type': 'signature_match',
                    'description': f'Matched signature: {description}',
                    'severity': 'high'
                })
                
        return findings
    
    def calculate_hash(self, file_path: str) -> Dict[str, str]:
        """Calculate multiple hashes for a file"""
        try:
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                data = f.read(4096)
                while data:
                    md5.update(data)
                    sha1.update(data)
                    sha256.update(data)
                    data = f.read(4096)
            
            return {
                'md5': md5.hexdigest(),
                'sha1': sha1.hexdigest(),
                'sha256': sha256.hexdigest()
            }
        except Exception as e:
            self.console.print(f"[yellow]Warning: Could not calculate hash for {file_path}: {str(e)}[/yellow]")
            return {'error': str(e)}
    
    def analyze_binary(self, file_path: str) -> Dict:
        """Analyze a binary file for potential security risks"""
        try:
            file_size = os.path.getsize(file_path)
            analysis = {
                'file_path': file_path,
                'size': file_size,
                'size_human': self._format_size(file_size),
                'mime_type': self.mime.from_file(file_path),
                'hashes': self.calculate_hash(file_path),
                'risks': []
            }

            # Check file size
            if file_size > 10 * 1024 * 1024:  # 10MB
                analysis['risks'].append({
                    'type': 'large_file',
                    'description': 'File size exceeds 10MB, potential DoS risk',
                    'severity': 'medium'
                })

            # Check file permissions
            if os.access(file_path, os.X_OK):
                analysis['risks'].append({
                    'type': 'executable',
                    'description': 'File has executable permissions',
                    'severity': 'medium'
                })
            
            # Read file data for further analysis (limit to first 1MB for large files)
            with open(file_path, 'rb') as f:
                data = f.read(min(file_size, 1024 * 1024))
            
            # Calculate entropy (high entropy can indicate encryption or packing)
            entropy = self.calculate_entropy(data)
            analysis['entropy'] = entropy
            
            if entropy > 7.5:  # Very high entropy
                analysis['risks'].append({
                    'type': 'high_entropy',
                    'description': f'High entropy ({entropy:.2f}/8.0) suggests encryption or packing, possible obfuscation',
                    'severity': 'high'
                })
            elif entropy > 6.5:  # Moderately high entropy
                analysis['risks'].append({
                    'type': 'medium_entropy',
                    'description': f'Medium-high entropy ({entropy:.2f}/8.0) may indicate compression or obfuscation',
                    'severity': 'medium'
                })
            
            # Check for known signatures
            signature_findings = self.check_signatures(data)
            analysis['risks'].extend(signature_findings)
            
            # Assess overall risk level
            risk_levels = [risk.get('severity', 'low') for risk in analysis['risks']]
            if 'high' in risk_levels:
                analysis['risk_level'] = 'high'
            elif 'medium' in risk_levels:
                analysis['risk_level'] = 'medium'
            elif risk_levels:
                analysis['risk_level'] = 'low'
            else:
                analysis['risk_level'] = 'safe'

            return analysis

        except Exception as e:
            self.console.print(f"[red]Error analyzing binary file {file_path}: {str(e)}[/red]")
            return {
                'file_path': file_path,
                'error': str(e)
            }
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024 or unit == 'TB':
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024