# Avikal Quick Start Guide

Get started with Avikal Time-Locked File Format in 5 minutes.

## Installation

```bash
# Install dependencies
pip install cryptography brotli
```

## Quick Example

### 1. Encode a File

```bash
python -m avikal_backend.cli encode myfile.pdf \
  --unlock "2026-03-15 10:00" \
  --password "MySecurePassword"
```

This creates `myfile.pdf.avk` that will unlock on March 15, 2026 at 10:00 AM IST.

### 2. Decode a File

```bash
python -m avikal_backend.cli decode myfile.pdf.avk \
  --password "MySecurePassword"
```

This extracts the original file (if unlock time has passed).

## Python API

```python
from datetime import datetime
from core.main import create_avk_file, extract_avk_file

# Encode
unlock_time = datetime(2026, 3, 15, 10, 0)  # IST
create_avk_file(
    input_filepath='exam.pdf',
    output_filepath='exam.avk',
    unlock_datetime=unlock_time,
    password='SecurePass123'
)

# Decode
extracted = extract_avk_file(
    avk_filepath='exam.avk',
    output_directory='.',
    password='SecurePass123'
)
print(f"Extracted to: {extracted}")
```

## Run Examples

```bash
# Run interactive examples
python -m avikal_backend.example

# Run test suite
python -m avikal_backend.test_avikal
```

## Key Features

✓ **Time-Locked**: Files unlock at specified IST time
✓ **Password Protected**: Mandatory password security
✓ **Fast**: Encodes any file size in <30 seconds
✓ **Secure**: AES-256-GCM + chess steganography
✓ **Tamper-Proof**: SHA-256 checksum verification

## Common Options

### Encode Options

```bash
--unlock, -u     Unlock time (IST) "YYYY-MM-DD HH:MM" [REQUIRED]
--password, -p   Password for protection [REQUIRED]
--output, -o     Output .avk file path [optional]
--username       User signature [optional]
--variations, -v Chess encoding parameter (default: 5) [optional]
```

### Decode Options

```bash
--password, -p   Password for decryption [REQUIRED]
--output-dir, -d Output directory (default: current) [optional]
```

## Error Messages

| Error | Meaning | Solution |
|-------|---------|----------|
| "Password is MANDATORY" | No password provided | Add --password flag |
| "Time capsule is locked" | Unlock time not reached | Wait until unlock time |
| "Incorrect password" | Wrong password | Use correct password |
| "Unlock time must be in future" | Past unlock time | Set future time |
| "Checksum verification failed" | File tampered | File corrupted/modified |

## Performance

Typical encoding times:
- 10 KB file: ~10 seconds
- 1 MB file: ~20 seconds
- 10 MB file: ~30 seconds

## Security Notes

1. **Use strong passwords**: Minimum 12 characters, mix of letters/numbers/symbols
2. **Keep passwords secure**: Store separately from .avk files
3. **Verify checksums**: System automatically verifies integrity
4. **Time-lock enforcement**: Cannot bypass without correct password

## Use Cases

### School Exams (PMBY)
```bash
# Teacher encodes exam paper
python -m avikal_backend.cli encode exam.pdf \
  --unlock "2026-03-15 09:00" \
  --password "ExamPassword2026" \
  --username "teacher@school.edu"

# Students receive exam.avk in advance
# File automatically unlocks at exam time
```

### Time Capsule
```bash
# Create time capsule for 1 year
python -m avikal_backend.cli encode letter.txt \
  --unlock "2027-01-01 00:00" \
  --password "NewYear2027"
```

### Scheduled Release
```bash
# Release document at specific time
python -m avikal_backend.cli encode announcement.pdf \
  --unlock "2026-06-01 12:00" \
  --password "ReleasePassword"
```

## Troubleshooting

### Import Errors
```bash
# Make sure you're in the project root
cd ChessPython

# Install dependencies
pip install -r core/main/requirements.txt
```

### Module Not Found
```bash
# Run from project root
python -m avikal_backend.cli encode ...
```

### Time Zone Issues
All times are in IST (Indian Standard Time, UTC+5:30). The system automatically handles timezone conversion.

## Next Steps

- Read [README.md](README.md) for detailed documentation
- Run [test_avikal.py](test_avikal.py) to verify installation
- Check [example.py](example.py) for more usage patterns

---

**Need Help?** Contact the development team or check the full documentation.
