with open('hexstrike_server.py', encoding='utf-8') as f:
    content = f.read()

patches = []

# --- ffuf ---
old = (
    '        command = f"ffuf"\n\n'
    '        if mode == "directory":\n'
    '            command += f" -u {url}/FUZZ -w {wordlist}"\n'
    '        elif mode == "vhost":\n'
    "            command += f\" -u {url} -H 'Host: FUZZ' -w {wordlist}\"\n"
    '        elif mode == "parameter":\n'
    '            command += f" -u {url}?FUZZ=value -w {wordlist}"\n'
    '        else:\n'
    '            command += f" -u {url} -w {wordlist}"\n\n'
    '        command += f" -mc {match_codes}"\n\n'
    '        if additional_args:\n'
    '            command += f" {additional_args}"\n\n'
    '        logger.info(f"🔍 Starting FFuf {mode} fuzzing: {url}")\n'
    '        result = execute_command(command)\n'
    '        logger.info(f"📊 FFuf fuzzing completed for {url}")\n'
    '        return jsonify(result)'
)
new = (
    '        if not _validate_target(url, max_len=2048):\n'
    '            return jsonify({"error": "invalid url"}), 400\n'
    '        if not _validate_path(wordlist):\n'
    '            return jsonify({"error": "invalid wordlist"}), 400\n'
    '        if additional_args and _SHELL_META_RE.search(additional_args):\n'
    '            return jsonify({"error": "invalid additional_args"}), 400\n\n'
    '        cmd: list[str] = ["ffuf"]\n'
    '        if mode == "directory":\n'
    '            cmd += ["-u", url.rstrip("/") + "/FUZZ", "-w", wordlist]\n'
    '        elif mode == "vhost":\n'
    '            cmd += ["-u", url, "-H", "Host: FUZZ", "-w", wordlist]\n'
    '        elif mode == "parameter":\n'
    '            cmd += ["-u", url + "?FUZZ=value", "-w", wordlist]\n'
    '        else:\n'
    '            cmd += ["-u", url, "-w", wordlist]\n'
    '        cmd += ["-mc", match_codes]\n'
    '        if additional_args:\n'
    '            cmd += additional_args.split()\n\n'
    '        logger.info("Starting FFuf %s fuzzing: %s", mode, url)\n'
    '        result = execute_command(cmd)\n'
    '        logger.info("FFuf fuzzing completed for %s", url)\n'
    '        return jsonify(result)'
)
patches.append((old, new))

# --- amass ---
old = (
    '        command = f"amass {mode}"\n\n'
    '        if mode == "enum":\n'
    '            command += f" -d {domain}"\n'
    '        else:\n'
    '            command += f" -d {domain}"\n\n'
    '        if additional_args:\n'
    '            command += f" {additional_args}"\n\n'
    '        logger.info(f"🔍 Starting Amass {mode}: {domain}")\n'
    '        result = execute_command(command)\n'
    '        logger.info(f"📊 Amass completed for {domain}")\n'
    '        return jsonify(result)'
)
new = (
    '        if not _validate_target(domain):\n'
    '            return jsonify({"error": "invalid domain"}), 400\n'
    '        if additional_args and _SHELL_META_RE.search(additional_args):\n'
    '            return jsonify({"error": "invalid additional_args"}), 400\n\n'
    '        cmd: list[str] = ["amass", mode, "-d", domain]\n'
    '        if additional_args:\n'
    '            cmd += additional_args.split()\n\n'
    '        logger.info("Starting Amass %s: %s", mode, domain)\n'
    '        result = execute_command(cmd)\n'
    '        logger.info("Amass completed for %s", domain)\n'
    '        return jsonify(result)'
)
patches.append((old, new))

# --- hashcat ---
old = (
    '        command = f"hashcat -m {hash_type} -a {attack_mode} {hash_file}"\n\n'
    '        if attack_mode == "0" and wordlist:\n'
    '            command += f" {wordlist}"\n'
    '        elif attack_mode == "3" and mask:\n'
    '            command += f" {mask}"\n\n'
    '        if additional_args:\n'
    '            command += f" {additional_args}"\n\n'
    '        logger.info(f"🔐 Starting Hashcat attack: mode {attack_mode}")\n'
    '        result = execute_command(command)\n'
    '        logger.info(f"📊 Hashcat attack completed")\n'
    '        return jsonify(result)'
)
new = (
    '        if not _validate_path(hash_file):\n'
    '            return jsonify({"error": "invalid hash_file"}), 400\n'
    '        if wordlist and not _validate_path(wordlist):\n'
    '            return jsonify({"error": "invalid wordlist"}), 400\n'
    '        if additional_args and _SHELL_META_RE.search(additional_args):\n'
    '            return jsonify({"error": "invalid additional_args"}), 400\n\n'
    '        cmd: list[str] = ["hashcat", "-m", str(hash_type), "-a", str(attack_mode), hash_file]\n'
    '        if attack_mode == "0" and wordlist:\n'
    '            cmd.append(wordlist)\n'
    '        elif attack_mode == "3" and mask:\n'
    '            cmd.append(mask)\n'
    '        if additional_args:\n'
    '            cmd += additional_args.split()\n\n'
    '        logger.info("Starting Hashcat attack: mode %s", attack_mode)\n'
    '        result = execute_command(cmd)\n'
    '        logger.info("Hashcat attack completed")\n'
    '        return jsonify(result)'
)
patches.append((old, new))

# --- subfinder ---
old = (
    '        command = f"subfinder -d {domain}"\n\n'
    '        if silent:\n'
    '            command += " -silent"\n\n'
    '        if all_sources:\n'
    '            command += " -all"\n\n'
    '        if additional_args:\n'
    '            command += f" {additional_args}"\n\n'
    '        logger.info(f"🔍 Starting Subfinder: {domain}")\n'
    '        result = execute_command(command)\n'
    '        logger.info(f"📊 Subfinder completed for {domain}")\n'
    '        return jsonify(result)'
)
new = (
    '        if not _validate_target(domain):\n'
    '            return jsonify({"error": "invalid domain"}), 400\n'
    '        if additional_args and _SHELL_META_RE.search(additional_args):\n'
    '            return jsonify({"error": "invalid additional_args"}), 400\n\n'
    '        cmd: list[str] = ["subfinder", "-d", domain]\n'
    '        if silent:\n'
    '            cmd.append("-silent")\n'
    '        if all_sources:\n'
    '            cmd.append("-all")\n'
    '        if additional_args:\n'
    '            cmd += additional_args.split()\n\n'
    '        logger.info("Starting Subfinder: %s", domain)\n'
    '        result = execute_command(cmd)\n'
    '        logger.info("Subfinder completed for %s", domain)\n'
    '        return jsonify(result)'
)
patches.append((old, new))

for old, new in patches:
    if old not in content:
        print(f"NOT FOUND: {repr(old[:80])}")
    else:
        content = content.replace(old, new, 1)
        print("Patched OK")

with open('hexstrike_server.py', 'w', encoding='utf-8') as f:
    f.write(content)
print("Batch 3b done")
