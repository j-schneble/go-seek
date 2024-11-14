import os

def is_file_corrupted(file_path, expected_signature):
    try:
        with open(file_path, 'rb') as file:
            actual_signature = file.read(len(expected_signature))
            return actual_signature == expected_signature
    except FileNotFoundError:
        print(f"No file found: {file_path}")
        return False
    except Exception as e:
        print(f"Error file checking {file_path}: {e}")

def scan_files(directory, expected_signature):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            print(file_path)
            is_file_corrupted(file_path, expected_signature)
            if is_file_corrupted(file_path, expected_signature):
                print("No corruption found.")
            else:
                print("Attention needed! Corruption found. ")

# Swap folders or directories in target directory path

if __name__ == "__main__":
    target_directory = r"/Users/me/downloads"
    expected_signature = b"\x89PNG\r\n\x1a\n"
    scan_files(target_directory, expected_signature)
