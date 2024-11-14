def isFileCorrupted(file_path, expected_signature):
    try:
        with open(file_path, 'rb') as file:
            actual_signature = file.read(len(expected_signature))
            return actual_signature == expected_signature
    except FileNotFoundError:
        print(f"No file found: {file_path}")
        return False
    except Exception as e:
        print(f"Error file checking {file_path}: {e}")
        return False


if __name__ == "__main__":
    file_path = r"/Users/me/Downloads/file.png"
    expected_signature = b"\x89PNG\r\n\x1a\n"
    isFileCorrupted(file_path, expected_signature)
    if isFileCorrupted(file_path, expected_signature):
        print("No corruption in file.")
    else:
        print("Corruption alert!")
