import os

# Folder Path
path = r"C:\Users\binhn\OneDrive\Desktop\NT521.M11\bandit\examples"
test_path = r"C:\Users\binhn\OneDrive\Desktop\NT521.M11\test.py"
# Change the directory
os.chdir(path)

# Read text File


def read_text_file(file_path):
    with open(file_path, 'r') as f:
        with open(test_path, "a") as file:
            file.write(f.read())


# iterate through all file
for file in os.listdir():
    # Check whether file is in text format or not
    if file.endswith(".py"):
        file_path = f"{path}\{file}"

        # call read text file function
        read_text_file(file_path)
