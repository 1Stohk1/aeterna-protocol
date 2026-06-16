import json
import os
import sys

def main():
    if len(sys.argv) < 4:
        print("Usage: python generate_genesis.py <home1> <home2> <template_path>")
        sys.exit(1)

    home1 = sys.argv[1]
    home2 = sys.argv[2]
    template_path = sys.argv[3]

    # Load template genesis
    with open(template_path, 'r') as f:
        genesis = json.load(f)

    # Load validator keys
    key1_path = os.path.join(home1, 'config', 'priv_validator_key.json')
    key2_path = os.path.join(home2, 'config', 'priv_validator_key.json')

    if not os.path.exists(key1_path):
        print(f"Error: Validator key not found at {key1_path}")
        sys.exit(1)
    if not os.path.exists(key2_path):
        print(f"Error: Validator key not found at {key2_path}")
        sys.exit(1)

    with open(key1_path, 'r') as f:
        key1 = json.load(f)
    with open(key2_path, 'r') as f:
        key2 = json.load(f)

    # Inject validators
    genesis['validators'] = [
        {
            'address': key1['address'],
            'pub_key': key1['pub_key'],
            'power': '100',
            'name': 'prometheus-1'
        },
        {
            'address': key2['address'],
            'pub_key': key2['pub_key'],
            'power': '100',
            'name': 'prometheus-2'
        }
    ]

    # Write output genesis.json to both node directories
    out1 = os.path.join(home1, 'config', 'genesis.json')
    out2 = os.path.join(home2, 'config', 'genesis.json')

    with open(out1, 'w') as f:
        json.dump(genesis, f, indent=2)
    with open(out2, 'w') as f:
        json.dump(genesis, f, indent=2)

    print(f"Successfully merged validator keys into genesis.json and distributed to:")
    print(f"  - {out1}")
    print(f"  - {out2}")

if __name__ == '__main__':
    main()
