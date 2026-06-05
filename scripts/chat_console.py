#!/usr/bin/env python3
"""
AETERNA Protocol — Interactive LLM CLI Client
Provides a local terminal interface to chat with the Ollama model.
"""

import os
import sys
import time
from typing import Optional

# Ensure the root directory is on the path so we can import core modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from core.llm_client import OllamaClient
except ImportError:
    print("\033[91mError: Cannot import core.llm_client. Run this script from the project root or scripts/ directory.\033[0m")
    sys.exit(1)

# ANSI Colors
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_DIM = "\033[2m"
COLOR_SYSTEM = "\033[95m"  # Magenta
COLOR_USER = "\033[96m"    # Cyan
COLOR_AI = "\033[92m"      # Green
COLOR_WARNING = "\033[93m" # Yellow
COLOR_ERROR = "\033[91m"   # Red
COLOR_CYAN_BG = "\033[46;30m"
COLOR_GRAY_BG = "\033[100;37m"

def print_banner():
    banner = f"""
{COLOR_BOLD}{COLOR_USER}======================================================================
     ___  ___________ ___________ _   _  ___  
    / _ \\|  ___|_   _|  ___| ___ \\ \\ | |/ _ \\ 
   / /_\\ \\ |__   | | | |__ | |_/ /  \\| / /_\\ \\\\
   |  _  |  __|  | | |  __||    /| . ` |  _  |
   | | | | |___  | | | |___| |\\ \\| |\\  | | | |
   \\_| |_/\\____/  \\_/\\____/\\_| \\_\\_| \\/\\_| |_/
                   
             AETERNA PROTOCOL — CONSOLE CHAT v0.3.0
======================================================================{COLOR_RESET}
    """
    print(banner)

def print_help():
    print(f"\n{COLOR_BOLD}Available Commands:{COLOR_RESET}")
    print(f"  {COLOR_USER}/help{COLOR_RESET}      Show this help message")
    print(f"  {COLOR_USER}/exit{COLOR_RESET}      Quit the chat session")
    print(f"  {COLOR_USER}/clear{COLOR_RESET}     Clear the console screen")
    print(f"  {COLOR_USER}/system{COLOR_RESET}    Set/change the system prompt (e.g. /system Tu sei un esperto...)")
    print(f"  {COLOR_USER}/status{COLOR_RESET}    Show Ollama daemon and model status")
    print()

def main():
    os.system("") # Enable ANSI escape characters in Windows terminal
    print_banner()
    
    # Initialize client
    client = OllamaClient(base_url="http://localhost:11434", model="llama3.2")
    
    # Check health and model availability
    print(f"{COLOR_DIM}Verifying connection to Ollama at {client.base_url}...{COLOR_RESET}", end="", flush=True)
    if not client.is_healthy():
        print(f"\r{COLOR_ERROR}Failed to connect to Ollama daemon on {client.base_url}.{COLOR_RESET}")
        print(f"{COLOR_WARNING}Please ensure Ollama is installed and running.{COLOR_RESET}")
        print("You can start it by running `ollama serve` in a separate terminal.")
        return
    print(f"\r{COLOR_AI}Ollama daemon connected successfully.                    {COLOR_RESET}")
    
    print(f"{COLOR_DIM}Checking availability of model '{client.model}'...{COLOR_RESET}", end="", flush=True)
    if not client.is_model_available():
        print(f"\r{COLOR_WARNING}Model '{client.model}' not found in Ollama.{COLOR_RESET}")
        print(f"Would you like to pull the model? (Run `ollama pull {client.model}` in your terminal first).")
        print(f"{COLOR_DIM}Attempting to continue anyway...{COLOR_RESET}")
    else:
        print(f"\r{COLOR_AI}Model '{client.model}' is available and ready.          {COLOR_RESET}")
        
    print_help()
    
    system_prompt = "Sei AETERNA, un'intelligenza artificiale cooperativa per l'analisi dei dati scientifici e crittografici."
    print(f"{COLOR_SYSTEM}System Prompt: {system_prompt}{COLOR_RESET}")
    print(f"{COLOR_DIM}Inizia a scrivere sotto. Premi Enter per inviare il messaggio.{COLOR_RESET}\n")
    
    while True:
        try:
            user_input = input(f"{COLOR_BOLD}{COLOR_USER}Tu > {COLOR_RESET}").strip()
            if not user_input:
                continue
                
            # Handle commands
            if user_input.startswith("/"):
                cmd_parts = user_input.split(" ", 1)
                cmd = cmd_parts[0].lower()
                
                if cmd == "/exit":
                    print(f"\n{COLOR_SYSTEM}Arrivederci! Connessione con AETERNA terminata.{COLOR_RESET}")
                    break
                elif cmd == "/help":
                    print_help()
                    continue
                elif cmd == "/clear":
                    os.system("cls" if os.name == "nt" else "clear")
                    print_banner()
                    print_help()
                    continue
                elif cmd == "/system":
                    if len(cmd_parts) > 1:
                        system_prompt = cmd_parts[1].strip()
                        print(f"{COLOR_SYSTEM}System Prompt aggiornato a: {system_prompt}{COLOR_RESET}\n")
                    else:
                        print(f"{COLOR_SYSTEM}System Prompt attuale: {system_prompt}{COLOR_RESET}")
                        print(f"Per cambiarlo, digita: /system <nuovo prompt>\n")
                    continue
                elif cmd == "/status":
                    healthy = client.is_healthy()
                    model_ok = client.is_model_available()
                    print(f"\n{COLOR_BOLD}Ollama Status:{COLOR_RESET}")
                    print(f"  URL: {client.base_url}")
                    print(f"  Daemon Running: {'✅ Sì' if healthy else '❌ No'}")
                    print(f"  Model '{client.model}' Installed: {'✅ Sì' if model_ok else '❌ No'}")
                    print()
                    continue
                else:
                    print(f"{COLOR_ERROR}Comando sconosciuto: {cmd}. Digita /help per la lista dei comandi.{COLOR_RESET}\n")
                    continue
            
            # Send to model
            print(f"\n{COLOR_BOLD}{COLOR_AI}AETERNA > {COLOR_RESET}", end="", flush=True)
            
            start_time = time.time()
            try:
                # Use generate with streaming simulation (since /api/generate in OllamaClient is non-streaming for now,
                # we show a brief thinking status, get the response, and print it)
                print(f"{COLOR_DIM}[elaborazione risposta...]{COLOR_RESET}\r", end="", flush=True)
                response = client.generate(prompt=user_input, system=system_prompt)
                elapsed = time.time() - start_time
                
                # Clear the "[elaborazione risposta...]" indicator
                sys.stdout.write("\033[K")
                
                # Print the response
                print(response)
                print(f"{COLOR_DIM}(Generato in {elapsed:.2f}s){COLOR_RESET}\n")
            except Exception as e:
                sys.stdout.write("\033[K")
                print(f"{COLOR_ERROR}Errore durante la generazione della risposta: {e}{COLOR_RESET}\n")
                
        except KeyboardInterrupt:
            print(f"\n\n{COLOR_SYSTEM}Arrivederci! (Interrotto da tastiera){COLOR_RESET}")
            break
        except Exception as e:
            print(f"\n{COLOR_ERROR}Errore inaspettato: {e}{COLOR_RESET}\n")

if __name__ == "__main__":
    main()
