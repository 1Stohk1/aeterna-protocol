import os
import sys

# Configurazione del generatore di contesto LLM
OUTPUT_FILE = "aeterna_context.txt"

# Estensioni per coprire l'intera architettura stratificata di AETERNA
ALLOWED_EXTENSIONS = {
    '.rs', '.py', '.go', '.jl', '.proto', 
    '.toml', '.json', '.md', '.sh', '.ps1'
}

# Cartelle da escludere per evitare file generati, compilati, cache o enormi dipendenze
EXCLUDE_DIRS = {
    'target', '.git', '__pycache__', 'node_modules', 
    '.venv', 'venv', 'logs', 'build', 'dist',
    '.aeternad_prometheus-1', '.aeternad_prometheus-2',
    'inbound', 'outbound', 'audit', 'cold_storage'
}

# File specifici da escludere (es. binari o file crittografici)
EXCLUDE_FILES = {
    'aeternad', 'aeternad.exe', 'cosmovisor.exe', 
    'keys.sealed', 'operator.pk', 'recovery_challenge.hex',
    'aeterna_context.txt', 'cold_storage.jsonl', 'ipfs_index.jsonl'
}

def generate_context(root_dir="."):
    print("Avvio della scansione per la generazione del contesto di AETERNA...")
    abs_root = os.path.abspath(root_dir)
    
    # Raccogliamo i file da includere per generare prima la struttura
    files_to_process = []
    
    for root, dirs, files in os.walk(abs_root):
        # Filtro directory in-place per os.walk
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        
        # Filtro addizionale per evitare sottocartelle annidate escluse
        rel_root = os.path.relpath(root, abs_root)
        rel_parts = rel_root.replace('\\', '/').split('/')
        if any(part in EXCLUDE_DIRS for part in rel_parts):
            continue
            
        for file in files:
            if file in EXCLUDE_FILES:
                continue
            if file.startswith("TASK-") and file.endswith(".json"):
                continue
            ext = os.path.splitext(file)[1].lower()
            if ext in ALLOWED_EXTENSIONS:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, abs_root)
                files_to_process.append((rel_path, full_path))

    # Ordina i file in ordine alfabetico per coerenza di lettura
    files_to_process.sort(key=lambda x: x[0])

    # Scrittura del file di output
    output_path = os.path.join(abs_root, OUTPUT_FILE)
    try:
        with open(output_path, 'w', encoding='utf-8') as outfile:
            outfile.write("=== AETERNA PROTOCOL — CONSOLIDATED CODEBASE CONTEXT ===\n")
            outfile.write("Questo file contiene l'intera codebase e la documentazione del progetto AETERNA.\n")
            outfile.write("Autori: Christian Peluso, Claude e Gemini\n")
            outfile.write("Versione: 1.0.0 Sovereign\n\n")
            
            # 1. Albero o mappa visiva della struttura dei file
            outfile.write("--- MAPPA STRUTTURALE DEI FILE INCLUSI ---\n")
            for rel_path, _ in files_to_process:
                outfile.write(f"  {rel_path}\n")
            outfile.write("-----------------------------------------\n\n")

            # 2. Concatenazione dei contenuti
            for rel_path, full_path in files_to_process:
                print(f"Elaborazione: {rel_path}")
                outfile.write(f"--- START OF FILE: {rel_path} ---\n")
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='replace') as infile:
                        outfile.write(infile.read())
                except Exception as e:
                    outfile.write(f"[Errore durante la lettura del file: {e}]\n")
                outfile.write(f"\n--- END OF FILE: {rel_path} ---\n\n")

        print(f"\nSuccesso! Contesto della codebase generato in: {output_path}")
        print(f"Numero totale di file consolidati: {len(files_to_process)}")
        
    except Exception as e:
        print(f"Errore nella generazione del file di contesto: {e}", file=sys.stderr)

if __name__ == "__main__":
    generate_context()
