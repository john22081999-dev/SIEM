import time

with open('sample_auth.txt', 'r') as file:
    file.seek(0, 2)              # jump to end
    while True:
        line = file.readline()
        if line:
            print(line.strip())
        else:
            time.sleep(0.5)
