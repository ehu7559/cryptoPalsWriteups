#Get lines
f = open("8.txt","r")
ls = f.readlines()
f.close()

highest_score = 0

for line in ls:
    #Count the blocks' matches
    blocks = []
    num_blocks = len(line) // 32 #Used because hex is twice as space-intensive
    #Chunkify it
    for i in range(num_blocks):
        blocks.append(line[32 * i, 32 * (i + 1))
    
    #Count!
    highest_reps = 0
    for i in range(num_blocks):
        num_reps = 0
        for j in range(num_blocks):
            if blocks[i] == blocks[j]:
                num_reps += 1
        if num_reps > highest_reps:
            highest_reps = num_reps
    
    if highest_reps >= highest_score:
        highest_score = highest_reps
        print(line + " \t" + str(highest_score))