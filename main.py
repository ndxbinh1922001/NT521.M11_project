def scan_func(a):
    print("==============================================================================")
    data = a.split('|')
    with open("test.py", "r") as file:
        lines = file.readlines()
    location = 1
    bug_location = []
    line_bug = []
    for line in lines:
        if (data[0] in line):
            bug_location.append(location)
            line_bug.append(line)
        location += 1
    print("Issue:", data[1])
    bug_location = list(map(str, bug_location))
    print("Location: line", ", ".join(bug_location))
    i = 0
    for line in line_bug:
        print(bug_location[i]+"\t" + line, end="")
        i += 1
    print("\nDetail:", end="")
    for i in range(2, len(data)):
        print("\n\t", data[i], end="")


def main():
    with open("data.txt", "r") as file:
        lines = file.readlines()
    for line in lines:
        scan_func(line)


if __name__ == "__main__":
    main()
