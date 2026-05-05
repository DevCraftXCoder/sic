with open('hexstrike_server.py', encoding='utf-8') as f:
    content = f.read()

patches = []

# --- metasploit ---
patches.append((
    '        command = f"msfconsole -q -r {resource_file}"\n\n        logger.info(f"🚀 Starting Metasploit module: {module}")\n        result = execute_command(command)',
    '        if not _validate_path(resource_file):\n            return jsonify({"error": "invalid resource_file path"}), 400\n\n        cmd: list[str] = ["msfconsole", "-q", "-r", resource_file]\n\n        logger.info("Starting Metasploit module: %s", module)\n        result = execute_command(cmd)'
))

# --- john ---
old_john = (
    '        command = f"john"\n\n        if format_type:\n            command += f" --format={format_type}"\n\n        if wordlist:\n            command += f" --wordlist={wordlist}"\n\n        if additional_args:\n            command += f" {additional_args}"\n\n        command += f" {hash_file}"\n\n'
    '        logger.info(f"🔐 Starting John the Ripper: {hash_file}")\n        result = execute_command(command)\n'
    '        logger.info(f"📊 John the Ripper completed")\n        return jsonify(result)'
)
new_john = (
    '        if not _validate_path(hash_file):\n            return jsonify({"error": "invalid hash_file"}), 400\n'
    '        if wordlist and not _validate_path(wordlist):\n            return jsonify({"error": "invalid wordlist"}), 400\n'
    '        if additional_args and _SHELL_META_RE.search(additional_args):\n            return jsonify({"error": "invalid additional_args"}), 400\n\n'
    '        cmd: list[str] = ["john"]\n        if format_type:\n            cmd += [f"--format={format_type}"]\n        if wordlist:\n            cmd += [f"--wordlist={wordlist}"]\n        if additional_args:\n            cmd += additional_args.split()\n        cmd.append(hash_file)\n\n'
    '        logger.info("Starting John the Ripper: %s", hash_file)\n        result = execute_command(cmd)\n'
    '        logger.info("John the Ripper completed")\n        return jsonify(result)'
)
patches.append((old_john, new_john))

# --- wpscan ---
patches.append((
    '        command = f"wpscan --url {url}"\n\n        if additional_args:\n            command += f" {additional_args}"\n\n        logger.info(f"🔍 Starting WPScan: {url}")\n        result = execute_command(command)\n        logger.info(f"📊 WPScan completed for {url}")\n        return jsonify(result)',
    '        if not _validate_target(url, max_len=2048):\n            return jsonify({"error": "invalid url"}), 400\n        if additional_args and _SHELL_META_RE.search(additional_args):\n            return jsonify({"error": "invalid additional_args"}), 400\n\n        cmd: list[str] = ["wpscan", "--url", url]\n        if additional_args:\n            cmd += additional_args.split()\n\n        logger.info("Starting WPScan: %s", url)\n        result = execute_command(cmd)\n        logger.info("WPScan completed for %s", url)\n        return jsonify(result)'
))

# --- enum4linux ---
patches.append((
    '        command = f"enum4linux {additional_args} {target}"\n\n        logger.info(f"🔍 Starting Enum4linux: {target}")\n        result = execute_command(command)\n        logger.info(f"📊 Enum4linux completed for {target}")\n        return jsonify(result)',
    '        if not _validate_target(target):\n            return jsonify({"error": "invalid target"}), 400\n        if additional_args and _SHELL_META_RE.search(additional_args):\n            return jsonify({"error": "invalid additional_args"}), 400\n\n        cmd: list[str] = ["enum4linux"]\n        if additional_args:\n            cmd += additional_args.split()\n        cmd.append(target)\n\n        logger.info("Starting Enum4linux: %s", target)\n        result = execute_command(cmd)\n        logger.info("Enum4linux completed for %s", target)\n        return jsonify(result)'
))

for old, new in patches:
    if old not in content:
        print(f"NOT FOUND: {old[:80]}")
    else:
        content = content.replace(old, new, 1)
        print(f"Patched: {old[:60]}")

with open('hexstrike_server.py', 'w', encoding='utf-8') as f:
    f.write(content)
print("Batch 3a done")
