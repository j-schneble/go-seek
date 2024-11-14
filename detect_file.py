import os

def is_malicious_file(file_path, malicious_signature):
    try:
        with open(file_path, "rb") as file:
            file_content = file.read()
            if malicious_signature in file_content:
                return True
        return False
    except FileNotFoundError:
        print("No file found.")
        return False

if __name__ == "__main__":

    malicious_signature = b"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    file_path = r"/Users/me/Downloads/file.png"  # Replace with the path to the file you want to scan.

    if is_malicious_file(file_path, malicious_signature):
        print("Detected malicious file.")
        input('Keep or delete malicious file')
        os.remove(file_path)
        print("Deleted malicious file")
    else:
        print("Clean file detection.")
