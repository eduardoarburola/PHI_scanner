import os
import re
from PyPDF2 import PdfReader
import mammoth
from pyrtf_ng.reader import RtfReader
from pyrtf_ng.document import Document

def scan_text(file_path):
    """Scan a plain text file for PHI patterns."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            return search_phi(content)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return []

def scan_pdf(file_path):
    """Scan a PDF file for PHI patterns."""
    try:
        reader = PdfReader(file_path)
        content = ""
        for page in reader.pages:
            content += page.extract_text()
        return search_phi(content)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return []

def scan_docx(file_path):
    """Scan a Word file for PHI patterns using mammoth."""
    try:
        with open(file_path, "rb") as docx_file:
            result = mammoth.extract_raw_text(docx_file)
            content = result.value  # Extracted text
            return search_phi(content)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return []

def scan_rtf(file_path):
    """Scan an RTF file for PHI patterns using pyrtf-ng."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            reader = RtfReader()
            doc = reader.read(file)
            content = ''.join([str(paragraph) for paragraph in doc.paragraphs])
            return search_phi(content)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return []

def search_phi(content):
    """Search for PHI patterns in the given content."""
    patterns = [
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN pattern
        r'\b\d{10}\b',             # Generic 10-digit number (e.g., phone)
        r'\b[A-Z]{2}\d{7}\b',      # Example: Passport-like pattern
        r'\b(A|B|AB|O)[+-]\b',     # Blood type pattern
    ]
    matches = []
    for pattern in patterns:
        matches.extend(re.findall(pattern, content))
    return matches

def scan_directory(directory):
    """Scan a directory for PHI in supported file types."""
    results = {}
    for root, _, files in os.walk(directory):
        print(f"Scanning directory: {root}")
        # Skip directories containing '/Library/'
        if 'Library' in root:
            continue

        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith('.txt'):
                matches = scan_text(file_path)
            elif file.endswith('.pdf'):
                matches = scan_pdf(file_path)
            elif file.endswith('.docx'):
                matches = scan_docx(file_path)
            elif file.endswith('.rtf'):
                matches = scan_rtf(file_path)
            else:
                continue

            if matches:
                results[file_path] = matches
    return results

def main():
    print("PHI Scanner")
    print("1. Scan entire hard drive")
    print("2. Scan current user's directory")
    choice = input("Enter your choice (1 or 2): ")

    if choice == '1':
        directory = '/'
    elif choice == '2':
        directory = os.path.expanduser('~')
    else:
        print("Invalid choice. Exiting.")
        return

    print(f"Scanning directory: {directory}")
    results = scan_directory(directory)

    with open("Results.txt", "w") as output_file:
        if results:
            output_file.write("Potential PHI found:\n")
            for file_path, matches in results.items():
                output_file.write(f"\nFile: {file_path}\n")
                for match in matches:
                    output_file.write(f"  Match: {match}\n")
            print("Results have been saved to Results.txt")
        else:
            output_file.write("No PHI found.\n")
            print("No PHI found. Results have been saved to Results.txt")

if __name__ == "__main__":
    main()
