from utils import PC1, PC2

def PC1Mapping(text):
    binary = ''.join(format(ord(char), '08b') for char in text)
    binary = binary.zfill((len(binary) + 63) // 64 * 64)
    result = ''.join(binary[i - 1] for i in PC1)
    print(len(binary))
    return result


def keyGenerator(result, round):
    shift_pattern = {
        1: 1, 2: 1, 3: 2, 4: 2, 5: 2, 6: 2, 7: 2, 8: 2, 
        9: 1, 10: 2, 11: 2, 12: 2, 13: 2, 14: 2, 15: 2, 16: 1
    }
    left = result[:28]
    right = result[28:]
    
    shifts = shift_pattern.get(round, 1)  
    # print("right before", right)
    # print(f"round number {round} and number of shifts {shifts}")
    left = left[shifts:] + left[:shifts] 
    right = right[shifts:] + right[:shifts]  
    # print("right after", right) 

    return left + right  


def PC2Mapping(key):
    if len(key) != 56:
        raise ValueError("Key must be 56 bits long")
    result = ''.join(key[i - 1] for i in PC2)
    return result