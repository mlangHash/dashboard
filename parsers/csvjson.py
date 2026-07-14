import csv
import json
from pathlib import Path

def convert_csv_to_json():
    # Base paths
    base_dir = Path(__file__).resolve().parent.parent
    csv_dir = base_dir / "files" / "CSV"
    output_dir = base_dir / "files"

    if not csv_dir.exists():
        print(f"Directory not found: {csv_dir}")
        return

    # Find all CSV files in files/CSV
    csv_files = list(csv_dir.glob("*.csv"))
    print(f"Found {len(csv_files)} CSV files to convert.")

    for csv_file in csv_files:
        #files/CSV/pixel_devices.csv -> files/pixel_devices.json
        json_filename = csv_file.stem + ".json"
        json_file = output_dir / json_filename

        print(f"Converting {csv_file.name} -> {json_filename}...")

        records = []
        try:
            with open(csv_file, mode="r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Clean up keys and values (strip whitespace)
                    cleaned_row = {k.strip(): v.strip() for k, v in row.items() if k is not None}
                    records.append(cleaned_row)

            # Save as JSON
            with open(json_file, mode="w", encoding="utf-8") as f:
                json.dump(records, f, indent=4)

            print(f"Saved {len(records)} records to {json_file}")
        except Exception as e:
            print(f"Error converting {csv_file.name}: {e}")

if __name__ == "__main__":
    convert_csv_to_json()
