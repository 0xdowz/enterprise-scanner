import os
import magic
import math
import hashlib
import re
import struct
from typing import List, Dict, Optional, Tuple, Set
from rich.console import Console
from rich.progress import track

class EnhancedBinaryDetector:
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
            '.lib', '.a',  # Static libraries
            '.wasm',  # WebAssembly
            '.swf',  # Flash
            '.dex'   # Android Dalvik Executable
        }
        
        # Known malicious signatures (hex patterns)
        self.malicious_signatures = {
            b'\x4D\x5A\x90\x00': 'Windows PE executable',
            b'\x7F\x45\x4C\x46': 'ELF executable',
            b'\xCA\xFE\xBA\xBE': 'Java class file',
            b'\xCF\xFA\xED\xFE': 'Mach-O binary (macOS)',
            b'\x50\x4B\x03\x04': 'ZIP archive (may contain malicious code)',
            b'\x52\x61\x72\x21': 'RAR archive (may contain malicious code)',
            b'\xD0\xCF\x11\xE0': 'Microsoft Office document (OLE)',
            b'\x25\x50\x44\x46': 'PDF document',
            b'\x7B\x5C\x72\x74': 'RTF document',
            b'\x23\x21': 'Shell script',
            b'\x64\x65\x78\x0A': 'DEX file (Android)',
            b'\xAC\xED\x00\x05': 'Java serialized object',
            b'\x46\x57\x53': 'Flash SWF file',
            b'\x00\x61\x73\x6D': 'WebAssembly binary'
        }
        
        # Known vulnerable strings and patterns
        self.vulnerable_patterns = {
            re.compile(b'eval\\s*\\('): 'JavaScript eval() usage',
            re.compile(b'exec\\s*\\('): 'Command execution function',
            re.compile(b'system\\s*\\('): 'System command execution',
            re.compile(b'Runtime\\.getRuntime\\(\\)\\.exec'): 'Java Runtime exec',
            re.compile(b'ProcessBuilder'): 'Java ProcessBuilder',
            re.compile(b'os\\.system'): 'Python os.system',
            re.compile(b'subprocess'): 'Python subprocess',
            re.compile(b'child_process'): 'Node.js child_process',
            re.compile(b'__VIEWSTATE'): '.NET ViewState (potentially unencrypted)',
            re.compile(b'PRIVATE KEY'): 'Private key material',
            re.compile(b'password\\s*='): 'Hardcoded password',
            re.compile(b'api[_-]?key'): 'API key',
            re.compile(b'secret[_-]?key'): 'Secret key',
            re.compile(b'BEGIN RSA PRIVATE KEY'): 'RSA private key',
            re.compile(b'jdbc:[a-z]+://'): 'JDBC connection string'
        }
        
        # Known malware strings
        self.malware_strings = {
            b'TVqQAAMAAAAEAAAA': 'Base64 encoded PE header',
            b'TVpQAAMAAAAEAAAA': 'Base64 encoded MZ header',
            b'powershell -e': 'PowerShell encoded command',
            b'cmd.exe /c': 'Command shell execution',
            b'WScript.Shell': 'Windows Script Host',
            b'CreateObject': 'ActiveX object creation',
            b'WSH.Run': 'Windows Script Host execution',
            b'document.write(unescape': 'JavaScript obfuscation technique',
            b'eval(function(p,a,c,k,e,d)': 'JavaScript packer',
            b'String.fromCharCode': 'JavaScript character code obfuscation'
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
            if not mime_type.startswith(('text/', 'application/json', 'application/xml', 'application/javascript')):
                return True
                
            # Additional check for binary content
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                # Check for null bytes which typically indicate binary content
                if b'\x00' in chunk:
                    return True
                    
            return False

        except Exception as e:
            self.console.print(f"[yellow]Warning: Could not determine if {file_path} is binary: {str(e)}[/yellow]")
            return False

    def scan_directory(self, directory: str) -> Dict[str, List[str]]:
        """Scan a directory for binary files"""
        result = {
            'binary_files': [],
            'text_files': [],
            'suspicious_files': []
        }

        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    if self.is_binary_file(file_path):
                        result['binary_files'].append(file_path)
                        # Quick check for suspicious binary files
                        analysis = self.analyze_binary(file_path)
                        if analysis.get('risk_level') in ['high', 'medium']:
                            result['suspicious_files'].append(file_path)
                    else:
                        result['text_files'].append(file_path)
                except Exception as e:
                    self.console.print(f"[yellow]Error scanning {file_path}: {str(e)}[/yellow]")

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
        
        # Check for known file signatures
        for signature, description in self.malicious_signatures.items():
            if signature in data[:1024]:  # Check first 1KB for efficiency
                findings.append({
                    'type': 'signature_match',
                    'description': f'Matched signature: {description}',
                    'severity': 'medium'
                })
        
        # Check for vulnerable patterns
        for pattern, description in self.vulnerable_patterns.items():
            if pattern.search(data):
                findings.append({
                    'type': 'vulnerable_pattern',
                    'description': f'Found vulnerable pattern: {description}',
                    'severity': 'high'
                })
                
        # Check for known malware strings
        for string, description in self.malware_strings.items():
            if string in data:
                findings.append({
                    'type': 'malware_string',
                    'description': f'Found malware indicator: {description}',
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
    
    def check_pe_characteristics(self, file_path: str) -> Dict:
        """Check PE file characteristics for suspicious attributes"""
        result = {
            'is_pe': False,
            'characteristics': [],
            'suspicious_sections': []
        }
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read(2)
                if data != b'MZ':
                    return result
                    
                # It's a PE file
                result['is_pe'] = True
                
                # Read e_lfanew field at offset 0x3C
                f.seek(0x3C)
                e_lfanew = struct.unpack('<I', f.read(4))[0]
                
                # Go to PE header
                f.seek(e_lfanew)
                if f.read(4) != b'PE\x00\x00':
                    return result
                    
                # Read characteristics
                f.seek(e_lfanew + 22)  # Offset to characteristics
                characteristics = struct.unpack('<H', f.read(2))[0]
                
                if characteristics & 0x0002:  # IMAGE_FILE_EXECUTABLE_IMAGE
                    result['characteristics'].append('executable')
                if characteristics & 0x2000:  # IMAGE_FILE_DLL
                    result['characteristics'].append('dll')
                    
                # TODO: Add more PE analysis like section names, imports, etc.
                
        except Exception as e:
            self.console.print(f"[yellow]Error analyzing PE file {file_path}: {str(e)}[/yellow]")
            
        return result
    
    def analyze_binary(self, file_path: str) -> Dict:
        """Analyze a binary file for potential security risks"""
        try:
            if not os.path.exists(file_path):
                return {'error': 'File does not exist'}
                
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
            
            # Check for known signatures and patterns
            signature_findings = self.check_signatures(data)
            analysis['risks'].extend(signature_findings)
            
            # Check PE file characteristics if applicable
            if file_path.lower().endswith('.exe') or file_path.lower().endswith('.dll'):
                pe_analysis = self.check_pe_characteristics(file_path)
                if pe_analysis['is_pe']:
                    analysis['pe_info'] = pe_analysis
                    if 'executable' in pe_analysis['characteristics']:
                        analysis['risks'].append({
                            'type': 'pe_executable',
                            'description': 'PE executable file detected',
                            'severity': 'medium'
                        })
            
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
            return {'error': str(e)}
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} bytes"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.2f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"