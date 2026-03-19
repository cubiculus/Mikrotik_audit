# 🔐 SSH Security Setup Guide

## Security Policy

This tool uses **`RejectPolicy()`** for SSH host key verification. This is the most secure policy that protects against Man-in-the-Middle (MITM) attacks.

### Why RejectPolicy()?

| Policy | Behavior | Security Level |
|--------|----------|----------------|
| **`RejectPolicy()`** | Rejects unknown hosts | 🔒 **Maximum** |
| `WarningPolicy()` | Warns but connects | ⚠️ Medium |
| `AutoAddPolicy()` | Auto-adds to known_hosts | ⚠️ Low |

**RejectPolicy()** requires the router's public SSH key to be pre-added to your `known_hosts` file before connecting.

---

## 🚀 First-Time Setup

### Step 1: Add Router's SSH Key

**Windows PowerShell:**
```powershell
ssh-keyscan -H 192.168.1.1 | Add-Content $env:USERPROFILE\.ssh\known_hosts
```

**Linux/Mac:**
```bash
ssh-keyscan -H 192.168.1.1 >> ~/.ssh/known_hosts
```

Replace `192.168.1.1` with your router's IP address.

### Step 2: Verify Key Was Added

**Windows:**
```powershell
Get-Content $env:USERPROFILE\.ssh\known_hosts | Select-String "192.168.1.1"
```

**Linux/Mac:**
```bash
grep "192.168.1.1" ~/.ssh/known_hosts
```

You should see output like:
```
192.168.1.1 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...
```

### Step 3: Run Audit

```bash
# Set password
$env:MIKROTIK_PASSWORD="your_password"  # PowerShell
export MIKROTIK_PASSWORD="your_password"  # Linux/Mac

# Run audit
python -m src.cli --ssh-user admin --router-ip 192.168.1.1
```

---

## 🔑 Alternative: SSH Key Authentication

Instead of password authentication, you can use SSH keys for better security.

### Generate SSH Key

```bash
ssh-keygen -t ed25519 -C "mikrotik-audit"
```

### Add Public Key to Router

1. **Via WinBox:**
   - Open WinBox → System → Users
   - Select your user → Click "SSH Keys"
   - Paste your public key from `~/.ssh/id_ed25519.pub`

2. **Via Terminal:**
   ```bash
   # Copy public key
   cat ~/.ssh/id_ed25519.pub

   # Paste into RouterOS terminal
   /user ssh-keys import public-key-file=your_key.pub user=admin
   ```

### Run Audit with SSH Key

```bash
python -m src.cli --ssh-user admin --ssh-key-file ~/.ssh/id_ed25519 --router-ip 192.168.1.1
```

---

## ❌ Troubleshooting

### Error: "Server not found in known_hosts"

```
SSHConnectionError: Server '192.168.1.1' not found in known_hosts
```

**Solution:**
1. Run `ssh-keyscan` command from Step 1
2. Verify the key was added (Step 2)
3. Check file permissions on known_hosts

### Error: "Permission denied"

**Windows:** Ensure PowerShell is running as Administrator
**Linux/Mac:** Check file permissions:
```bash
chmod 600 ~/.ssh/known_hosts
```

### Key Changed Warning

If you get a warning about host key changing:
```
WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!
```

This could indicate:
- Router was reset (normal)
- MITM attack (security concern)

**To fix (only if you trust the router):**
```bash
# Remove old key
ssh-keygen -R 192.168.1.1

# Add new key
ssh-keyscan -H 192.168.1.1 >> ~/.ssh/known_hosts
```

---

## 📍 Known_hosts File Locations

| OS | Path |
|----|------|
| **Windows** | `C:\Users\<User>\.ssh\known_hosts` |
| **Linux** | `/home/<user>/.ssh/known_hosts` |
| **Mac** | `/Users/<user>/.ssh/known_hosts` |

---

## 🔒 Best Practices

1. ✅ **Always verify host keys** before adding to known_hosts
2. ✅ **Use SSH keys** instead of passwords when possible
3. ✅ **Regularly update** known_hosts when routers are reset
4. ✅ **Use strong passwords** for SSH key passphrases
5. ✅ **Keep private keys secure** with proper file permissions

---

## 📚 Additional Resources

- [Paramiko Security Policies](https://docs.paramiko.org/en/latest/api/client.html)
- [SSH Best Practices](https://www.ssh.com/academy/ssh/best-practices)
- [OpenSSH known_hosts Format](https://man.openbsd.org/ssh#SSH_KNOWN_HOSTS_FILE_FORMAT)
