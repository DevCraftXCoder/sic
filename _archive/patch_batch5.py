with open('hexstrike_server.py', encoding='utf-8') as f:
    content = f.read()

patches = []

# --- volatility ---
patches.append((
    '        command = f"volatility -f {memory_file}"\n\n'
    '        if profile:\n'
    '            command += f" --profile={profile}"\n\n'
    '        command += f" {plugin}"\n\n'
    '        if additional_args:\n'
    '            command += f" {additional_args}"\n\n'
    '        logger.info(f"🧠 Starting Volatility analysis: {plugin}")\n'
    '        result = execute_command(command)\n'
    '        logger.info(f"📊 Volatility analysis completed")\n'
    '        return jsonify(result)',
    '        if not _validate_path(memory_file):\n'
    '            return jsonify({"error": "invalid memory_file"}), 400\n'
    '        if additional_args and _SHELL_META_RE.search(additional_args):\n'
    '            return jsonify({"error": "invalid additional_args"}), 400\n\n'
    '        cmd: list[str] = ["volatility", "-f", memory_file]\n'
    '        if profile:\n'
    '            cmd.append(f"--profile={profile}")\n'
    '        cmd.append(plugin)\n'
    '        if additional_args:\n'
    '            cmd += additional_args.split()\n\n'
    '        logger.info("Starting Volatility analysis: %s", plugin)\n'
    '        result = execute_command(cmd)\n'
    '        logger.info("Volatility analysis completed")\n'
    '        return jsonify(result)'
))

# --- msfvenom ---
patches.append((
    '        command = f"msfvenom -p {payload}"\n\n'
    '        if format_type:\n'
    '            command += f" -f {format_type}"\n\n'
    '        if output_file:\n'
    '            command += f" -o {output_file}"\n\n'
    '        if encoder:\n'
    '            command += f" -e {encoder}"\n\n'
    '        if iterations:\n'
    '            command += f" -i {iterations}"\n\n'
    '        if additional_args:\n'
    '            command += f" {additional_args}"\n\n'
    '        logger.info(f"🚀 Starting MSFVenom payload generation: {payload}")\n'
    '        result = execute_command(command)\n'
    '        logger.info(f"📊 MSFVenom payload generated")\n'
    '        return jsonify(result)',
    '        if _SHELL_META_RE.search(payload):\n'
    '            return jsonify({"error": "invalid payload"}), 400\n'
    '        if output_file and not _validate_path(output_file):\n'
    '            return jsonify({"error": "invalid output_file"}), 400\n'
    '        if additional_args and _SHELL_META_RE.search(additional_args):\n'
    '            return jsonify({"error": "invalid additional_args"}), 400\n\n'
    '        cmd: list[str] = ["msfvenom", "-p", payload]\n'
    '        if format_type:\n'
    '            cmd += ["-f", format_type]\n'
    '        if output_file:\n'
    '            cmd += ["-o", output_file]\n'
    '        if encoder:\n'
    '            cmd += ["-e", encoder]\n'
    '        if iterations:\n'
    '            cmd += ["-i", str(iterations)]\n'
    '        if additional_args:\n'
    '            cmd += additional_args.split()\n\n'
    '        logger.info("Starting MSFVenom payload generation: %s", payload)\n'
    '        result = execute_command(cmd)\n'
    '        logger.info("MSFVenom payload generated")\n'
    '        return jsonify(result)'
))

# --- gdb ---
patches.append((
    '        command = f"gdb {binary}"\n\n'
    '        if script_file:\n'
    '            command += f" -x {script_file}"\n\n'
    '        if commands:\n'
    '            temp_script = "/tmp/gdb_commands.txt"\n'
    '            with open(temp_script, "w") as f:\n'
    '                f.write(commands)\n'
    '            command += f" -x {temp_script}"\n\n'
    '        if additional_args:\n'
    '            command += f" {additional_args}"\n\n'
    '        command += " -batch"\n\n'
    '        logger.info(f"🔧 Starting GDB analysis: {binary}")\n'
    '        result = execute_command(command)\n\n'
    '        if commands and os.path.exists("/tmp/gdb_commands.txt"):\n'
    '            try:\n'
    '                os.remove("/tmp/gdb_commands.txt")\n'
    '            except:\n'
    '                pass\n\n'
    '        logger.info(f"📊 GDB analysis completed for {binary}")\n'
    '        return jsonify(result)',
    '        if not _validate_path(binary):\n'
    '            return jsonify({"error": "invalid binary"}), 400\n'
    '        if script_file and not _validate_path(script_file):\n'
    '            return jsonify({"error": "invalid script_file"}), 400\n\n'
    '        cmd: list[str] = ["gdb", binary]\n'
    '        if script_file:\n'
    '            cmd += ["-x", script_file]\n'
    '        if commands:\n'
    '            temp_script = "/tmp/gdb_commands.txt"\n'
    '            with open(temp_script, "w") as f:\n'
    '                f.write(commands)\n'
    '            cmd += ["-x", temp_script]\n'
    '        cmd.append("-batch")\n\n'
    '        logger.info("Starting GDB analysis: %s", binary)\n'
    '        result = execute_command(cmd)\n\n'
    '        if commands and os.path.exists("/tmp/gdb_commands.txt"):\n'
    '            try:\n'
    '                os.remove("/tmp/gdb_commands.txt")\n'
    '            except:\n'
    '                pass\n\n'
    '        logger.info("GDB analysis completed for %s", binary)\n'
    '        return jsonify(result)'
))

# --- radare2 ---
patches.append((
    '        if commands:\n'
    '            temp_script = "/tmp/r2_commands.txt"\n'
    '            with open(temp_script, "w") as f:\n'
    '                f.write(commands)\n'
    '            command = f"r2 -i {temp_script} -q {binary}"\n'
    '        else:\n'
    '            command = f"r2 -q {binary}"\n\n'
    '        if additional_args:\n'
    '            command += f" {additional_args}"\n\n'
    '        logger.info(f"🔧 Starting Radare2 analysis: {binary}")\n'
    '        result = execute_command(command)\n\n'
    '        if commands and os.path.exists("/tmp/r2_commands.txt"):\n'
    '            try:\n'
    '                os.remove("/tmp/r2_commands.txt")\n'
    '            except:\n'
    '                pass\n\n'
    '        logger.info(f"📊 Radare2 analysis completed for {binary}")\n'
    '        return jsonify(result)',
    '        if not _validate_path(binary):\n'
    '            return jsonify({"error": "invalid binary"}), 400\n\n'
    '        if commands:\n'
    '            temp_script = "/tmp/r2_commands.txt"\n'
    '            with open(temp_script, "w") as f:\n'
    '                f.write(commands)\n'
    '            cmd: list[str] = ["r2", "-i", temp_script, "-q", binary]\n'
    '        else:\n'
    '            cmd = ["r2", "-q", binary]\n\n'
    '        logger.info("Starting Radare2 analysis: %s", binary)\n'
    '        result = execute_command(cmd)\n\n'
    '        if commands and os.path.exists("/tmp/r2_commands.txt"):\n'
    '            try:\n'
    '                os.remove("/tmp/r2_commands.txt")\n'
    '            except:\n'
    '                pass\n\n'
    '        logger.info("Radare2 analysis completed for %s", binary)\n'
    '        return jsonify(result)'
))

# --- binwalk ---
patches.append((
    '        command = f"binwalk"\n\n'
    '        if extract:\n'
    '            command += " -e"\n\n'
    '        if additional_args:\n'
    '            command += f" {additional_args}"\n\n'
    '        command += f" {file_path}"\n\n'
    '        logger.info(f"🔧 Starting Binwalk analysis: {file_path}")\n'
    '        result = execute_command(command)\n'
    '        logger.info(f"📊 Binwalk analysis completed for {file_path}")\n'
    '        return jsonify(result)',
    '        if not _validate_path(file_path):\n'
    '            return jsonify({"error": "invalid file_path"}), 400\n'
    '        if additional_args and _SHELL_META_RE.search(additional_args):\n'
    '            return jsonify({"error": "invalid additional_args"}), 400\n\n'
    '        cmd: list[str] = ["binwalk"]\n'
    '        if extract:\n'
    '            cmd.append("-e")\n'
    '        if additional_args:\n'
    '            cmd += additional_args.split()\n'
    '        cmd.append(file_path)\n\n'
    '        logger.info("Starting Binwalk analysis: %s", file_path)\n'
    '        result = execute_command(cmd)\n'
    '        logger.info("Binwalk analysis completed for %s", file_path)\n'
    '        return jsonify(result)'
))

# --- ropgadget ---
patches.append((
    '        command = f"ROPgadget --binary {binary}"\n\n'
    '        if gadget_type:\n'
    "            command += f\" --only '{gadget_type}'\"\n\n"
    '        if additional_args:\n'
    '            command += f" {additional_args}"\n\n'
    '        logger.info(f"🔧 Starting ROPgadget search: {binary}")\n'
    '        result = execute_command(command)\n'
    '        logger.info(f"📊 ROPgadget search completed for {binary}")\n'
    '        return jsonify(result)',
    '        if not _validate_path(binary):\n'
    '            return jsonify({"error": "invalid binary"}), 400\n'
    '        if additional_args and _SHELL_META_RE.search(additional_args):\n'
    '            return jsonify({"error": "invalid additional_args"}), 400\n\n'
    '        cmd: list[str] = ["ROPgadget", "--binary", binary]\n'
    '        if gadget_type:\n'
    '            cmd += ["--only", gadget_type]\n'
    '        if additional_args:\n'
    '            cmd += additional_args.split()\n\n'
    '        logger.info("Starting ROPgadget search: %s", binary)\n'
    '        result = execute_command(cmd)\n'
    '        logger.info("ROPgadget search completed for %s", binary)\n'
    '        return jsonify(result)'
))

# --- checksec ---
patches.append((
    '        command = f"checksec --file={binary}"\n\n'
    '        logger.info(f"🔧 Starting Checksec analysis: {binary}")\n'
    '        result = execute_command(command)\n'
    '        logger.info(f"📊 Checksec analysis completed for {binary}")\n'
    '        return jsonify(result)',
    '        if not _validate_path(binary):\n'
    '            return jsonify({"error": "invalid binary"}), 400\n\n'
    '        cmd: list[str] = ["checksec", f"--file={binary}"]\n\n'
    '        logger.info("Starting Checksec analysis: %s", binary)\n'
    '        result = execute_command(cmd)\n'
    '        logger.info("Checksec analysis completed for %s", binary)\n'
    '        return jsonify(result)'
))

# --- xxd ---
patches.append((
    '        command = f"xxd -s {offset}"\n\n'
    '        if length:\n'
    '            command += f" -l {length}"\n\n'
    '        if additional_args:\n'
    '            command += f" {additional_args}"\n\n'
    '        command += f" {file_path}"\n\n'
    '        logger.info(f"🔧 Starting XXD hex dump: {file_path}")\n'
    '        result = execute_command(command)\n'
    '        logger.info(f"📊 XXD hex dump completed for {file_path}")\n'
    '        return jsonify(result)',
    '        if not _validate_path(file_path):\n'
    '            return jsonify({"error": "invalid file_path"}), 400\n'
    '        if additional_args and _SHELL_META_RE.search(additional_args):\n'
    '            return jsonify({"error": "invalid additional_args"}), 400\n\n'
    '        cmd: list[str] = ["xxd", "-s", str(offset)]\n'
    '        if length:\n'
    '            cmd += ["-l", str(length)]\n'
    '        if additional_args:\n'
    '            cmd += additional_args.split()\n'
    '        cmd.append(file_path)\n\n'
    '        logger.info("Starting XXD hex dump: %s", file_path)\n'
    '        result = execute_command(cmd)\n'
    '        logger.info("XXD hex dump completed for %s", file_path)\n'
    '        return jsonify(result)'
))

# --- strings ---
patches.append((
    '        command = f"strings -n {min_len}"\n\n'
    '        if additional_args:\n'
    '            command += f" {additional_args}"\n\n'
    '        command += f" {file_path}"\n\n'
    '        logger.info(f"🔧 Starting Strings extraction: {file_path}")\n'
    '        result = execute_command(command)\n'
    '        logger.info(f"📊 Strings extraction completed for {file_path}")\n'
    '        return jsonify(result)',
    '        if not _validate_path(file_path):\n'
    '            return jsonify({"error": "invalid file_path"}), 400\n'
    '        if additional_args and _SHELL_META_RE.search(additional_args):\n'
    '            return jsonify({"error": "invalid additional_args"}), 400\n\n'
    '        cmd: list[str] = ["strings", "-n", str(min_len)]\n'
    '        if additional_args:\n'
    '            cmd += additional_args.split()\n'
    '        cmd.append(file_path)\n\n'
    '        logger.info("Starting Strings extraction: %s", file_path)\n'
    '        result = execute_command(cmd)\n'
    '        logger.info("Strings extraction completed for %s", file_path)\n'
    '        return jsonify(result)'
))

# --- objdump ---
patches.append((
    '        command = f"objdump"\n\n'
    '        if disassemble:\n'
    '            command += " -d"\n'
    '        else:\n'
    '            command += " -x"\n\n'
    '        if additional_args:\n'
    '            command += f" {additional_args}"\n\n'
    '        command += f" {binary}"\n\n'
    '        logger.info(f"🔧 Starting Objdump analysis: {binary}")\n'
    '        result = execute_command(command)\n'
    '        logger.info(f"📊 Objdump analysis completed for {binary}")\n'
    '        return jsonify(result)',
    '        if not _validate_path(binary):\n'
    '            return jsonify({"error": "invalid binary"}), 400\n'
    '        if additional_args and _SHELL_META_RE.search(additional_args):\n'
    '            return jsonify({"error": "invalid additional_args"}), 400\n\n'
    '        cmd: list[str] = ["objdump"]\n'
    '        if disassemble:\n'
    '            cmd.append("-d")\n'
    '        else:\n'
    '            cmd.append("-x")\n'
    '        if additional_args:\n'
    '            cmd += additional_args.split()\n'
    '        cmd.append(binary)\n\n'
    '        logger.info("Starting Objdump analysis: %s", binary)\n'
    '        result = execute_command(cmd)\n'
    '        logger.info("Objdump analysis completed for %s", binary)\n'
    '        return jsonify(result)'
))

for old, new in patches:
    if old not in content:
        print(f"NOT FOUND: {repr(old[:80])}")
    else:
        content = content.replace(old, new, 1)
        print("Patched OK")

with open('hexstrike_server.py', 'w', encoding='utf-8') as f:
    f.write(content)
print("Batch 5 done")
